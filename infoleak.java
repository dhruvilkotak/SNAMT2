package com.zme.zmecontentassetprocessor.servlet;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.regex.Pattern;
import java.util.zip.DataFormatException;

import javax.annotation.Resource;
import javax.measure.unit.SI;
import javax.measure.unit.Unit;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ObjectUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.encoder.Encode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.HttpRequestHandler;

import com.amazon.ion.IonSystem;
import com.amazon.zmecontent.validation.FileValidator;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.sqs.AmazonSQSAsync;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zme.image.ZMEBufferedImage;
import com.zme.io.DiskBuffer;
import com.zme.io.MemoryBuffer;
import com.zme.io.StreamProcessException;
import com.zme.io.StreamProcessor;
import com.zme.zmecontentasset.AssetType;
import com.zme.zmecontentasset.AssetType.Endpoint;
import com.zme.zmecontentasset.AssetVersionMetadata;
import com.zme.zmecontentasset.MediaType;
import com.zme.zmecontentasset.Region;
import com.zme.zmecontentasset.accessor.CASCache;
import com.zme.zmecontentasset.util.ExpirationScheduler;
import com.zme.zmecontentassetprocessor.data.CAPSAssetRequest;
import com.zme.zmecontentassetprocessor.data.S3AssetMetadata;
import com.zme.zmecontentassetprocessor.exception.AssetNotFoundException;
import com.zme.zmecontentassetprocessor.exception.ImageDerivationException;
import com.zme.zmecontentassetprocessor.resource.AssetDeriver;
import com.zme.zmecontentassetprocessor.resource.DynamoDBHelper;
import com.zme.zmecontentassetprocessor.resource.S3Uploader;
import com.zme.zmecontentassetprocessor.resource.UploadModifier;
import com.zme.zmecontentassetprocessor.util.S3ClientFactory;
import com.zme.zmecontentassetprocessor.util.S3ClientFactory.EndpointNotFoundException;
import com.zme.zmecontentassetprocessor.validation.UploadVerifier;
import com.zme.zmecontentassetprocessor.validation.validators.FileSignatureValidator;

public class DefaultAssetServlet implements HttpRequestHandler {
    private static final long MAX_IN_MEMORY_BUFFER_SIZE = 100 * 1024 * 1024;
    private static final int DISK_BUFFER_CHUNK_SIZE = 512 * 1024;
    private static final int MEMORY_BUFFER_CHUNK_SIZE = 64 * 1024;
    private static final long ONE_SECOND  = 1000L;
    private static final long FIVE_SECONDS = 5 * ONE_SECOND;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();


    private static final Pattern AMAZON_URL_PATTERN =
            Pattern.compile("https?://(?:.*\\.)?(?:amazon|createspace)\\.com(?::\\d+)?");

    private static final String RFC112_FORMAT = "EEE, dd MMM yyyy HH:mm:ss zzz";
    //One year in seconds
    private static final long CACHE_MAX_AGE = 31536000;

    private final Logger log = Logger.getLogger(getClass());

    @Autowired
    protected ExecutorService executorService;

    @Autowired
    @Qualifier("dynamoHelper")
    protected DynamoDBHelper dynamoHelper;

    @Autowired
    protected ExpirationScheduler expirationScheduler;

    @Autowired
    protected FileValidator fileValidator;

    @Resource(name = "casCache")
    private CASCache casCache;

    @Resource(name = "retryingSQSClient")
    private AmazonSQSAsync sqsClient;

    @Resource(name = "scanQueueName")
    private String scanQueueName;

    @Resource(name = "uploadFinalizeQueueName")
    private String uploadFinalizeQueueName;

    @Resource(name="instanceRegion")
    private Region instanceRegion;

    @Resource(name = "ionSystem")
    private IonSystem ionSystem;

    @Resource(name = "s3ClientFactory")
    private S3ClientFactory clientFactory;

    protected S3Uploader getS3Uploader(Endpoint endpoint) {
        AmazonS3Client s3Client = clientFactory.getClient(endpoint);
        return new S3Uploader(dynamoHelper, s3Client, clientFactory.getBucket(endpoint), executorService, sqsClient,
                scanQueueName, uploadFinalizeQueueName, ionSystem, fileValidator);
    }

    // multipart uploads must never go through CSE. If they should be CSE they
    // will go to SSE and be reuploaded by the MultipartUploadFixerjob in CASDaemon
    protected S3Uploader getMultipartS3Uploader(CAPSAssetRequest request) {
        Endpoint endpoint = request.getEndpoint();
        if(Endpoint.CSE.equals(endpoint)) {
            endpoint = Endpoint.SSE;
        }
        AmazonS3Client s3Client = clientFactory.getClient(endpoint);
        return new S3Uploader(dynamoHelper, s3Client, clientFactory.getBucket(endpoint), executorService, sqsClient,
                scanQueueName, uploadFinalizeQueueName, ionSystem, fileValidator);
    }

    protected S3AssetMetadata performUpload(final CAPSAssetRequest request)
            throws NoSuchAlgorithmException, IOException, DataFormatException {
        long s3ClientRetrievalStartTime = System.currentTimeMillis();
        S3Uploader uploader = getS3Uploader(request.getEndpoint());
        long s3ClientRetrievalEndTime = System.currentTimeMillis();
        request.getMetrics().addTime("S3ClientRetrievalTime",
                s3ClientRetrievalEndTime - s3ClientRetrievalStartTime,
                SI.MILLI(SI.SECOND));
        request.getMetrics().addTime("DelayBeforeUploadBeginsTime",
                System.currentTimeMillis() - request.getAssetRequestCreatedTime(),
                SI.MILLI(SI.SECOND));
        return uploader.upload(request);
    }

    protected void setupMultipartUpload(final CAPSAssetRequest request) {
        getMultipartS3Uploader(request).setupMultipartUpload(request);
    }

    protected S3AssetMetadata performMultipartUpload(final CAPSAssetRequest request)
            throws NoSuchAlgorithmException {
        return getMultipartS3Uploader(request).uploadPart(request);
    }

    protected void abortMultipartUpload(final CAPSAssetRequest request) {
        getMultipartS3Uploader(request).abortMultipartUpload(request);
    }

    protected Future<S3AssetMetadata> completeMultipartUpload(final CAPSAssetRequest request) {
        return executorService.submit(new Callable<S3AssetMetadata>() {
            @Override
            public S3AssetMetadata call() throws Exception {
                return getMultipartS3Uploader(request).completeMultipartUpload(request);
            }
        });
    }

    @Override
    public void handleRequest(HttpServletRequest request,
                              HttpServletResponse response) throws ServletException, IOException {
        HttpMethod method = HttpMethod.valueOf(request.getMethod());
        AccessibleServletRequest accessibleRequest =
                (AccessibleServletRequest) request;
        AccessibleServletResponse accessibleResponse =
                (AccessibleServletResponse) response;

        switch (method) {
            case GET:
                doGet(accessibleRequest, accessibleResponse);
                break;
            case HEAD:
                doHead(accessibleRequest, accessibleResponse);
                break;
            case PUT:
                doPut(accessibleRequest, accessibleResponse);
                break;
            case POST:
                doPost(accessibleRequest, accessibleResponse);
                break;
            case DELETE:
                doDelete(accessibleRequest, accessibleResponse);
                break;
            case OPTIONS:
                doOptions(accessibleRequest, accessibleResponse);
                break;
        }
    }

    protected void doDelete(AccessibleServletRequest request,
                            AccessibleServletResponse response) throws ServletException, IOException {
        CAPSAssetRequest assetRequest = new CAPSAssetRequest(request, false, casCache, instanceRegion);
        String assetId = assetRequest.getId();
        String assetType = assetRequest.getAssetType().getName();
        String assetIndex = assetRequest.getAssetIndex();
        Long assetVersion = assetRequest.getAssetVersionId();
        long nowMillis = System.currentTimeMillis();

        if (assetVersion == null) {
            assetVersion = dynamoHelper.getLatestVersionID(assetId, assetType, assetIndex);
        }
        if (assetVersion == null) {
            return;  // AssetNotFound is counted as success and some system tests rely on this
        }

        expirationScheduler.scheduleExpiration(assetId, assetType, assetIndex, assetVersion, nowMillis);
        dynamoHelper.delete(assetId, assetType, assetIndex, assetVersion, nowMillis);
    }

    protected void addCacheHeaders(CAPSAssetRequest request, AccessibleServletResponse response, Date lastModifiedDate) {
        SimpleDateFormat formatter = new SimpleDateFormat(RFC112_FORMAT);
        long urlAge = (request.getUrlExpirationDate() / 1000) - (new Date().getTime() / 1000);
        Date urlExpiration = new Date(request.getUrlExpirationDate());
        if(urlAge > CACHE_MAX_AGE) {
            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.YEAR, 1);
            urlExpiration = calendar.getTime();

            urlAge = CACHE_MAX_AGE;
        }
        String expires = formatter.format(urlExpiration);
        String cacheControl = String.format("public, max-age=%s", urlAge);
        String lastModified = formatter.format(lastModifiedDate);

        response.setHeader("Cache-Control", cacheControl);
        response.setHeader("Expires", expires);
        response.setHeader("Last-Modified", lastModified);
    }

    protected void doGet(AccessibleServletRequest request,
                         AccessibleServletResponse response) {
        CAPSAssetRequest assetRequest = new CAPSAssetRequest(request, false, casCache, instanceRegion);

        //Used by the metrics filter
        response.setAssetType(assetRequest.getAssetType().getName());
        response.setNamespace(assetRequest.getAssetType().getNamespace());

        AssetVersionMetadata metadata = dynamoHelper.get(assetRequest);
        if(metadata == null || metadata.isDeleted()) {
            throw new AssetNotFoundException(request.toString());
        }

        Endpoint endpoint = metadata.getEndpointOverride();
        if (endpoint == null) {
            endpoint = assetRequest.getEndpoint();
        }
        GetObjectRequest getRequest = new GetObjectRequest(clientFactory.getBucket(endpoint),
                assetRequest.getKey());

        getRequest.setVersionId(metadata.getS3VersionIdForRegion(instanceRegion));

        AmazonS3 s3Client = clientFactory.getClient(endpoint);

        S3Object object = s3Client.getObject(getRequest);
        ObjectMetadata objectMetadata = object.getObjectMetadata();

        String contentType = objectMetadata.getContentType();
        response.setContentType(contentType);

        try {
            if (metadata.getFileSize() != -1) {
                response.setHeader("Content-Length",
                        Long.toString(metadata.getFileSize()));
            }
            if (StringUtils.isNotEmpty(metadata.getChecksum())) {
                response.setHeader("ETag",
                        String.format("\"%s\"", metadata.getChecksum()));
            }
            if (StringUtils.isNotEmpty(assetRequest.getContentDisposition())) {
                response.setHeader("Content-Disposition",
                        assetRequest.getContentDisposition());
            }

            setHttpAccessControl(request, response);
            addCacheHeaders(assetRequest, response, metadata.getTimestamp());
            //catch the BufferedDownload time
            long startBufferedDownloadTime = System.currentTimeMillis();
            assetRequest.getMetrics().addTime("DelayBeforeDownloadBeginsTime",
                    startBufferedDownloadTime - assetRequest.getAssetRequestCreatedTime(), SI.MILLI(SI.SECOND));
            doBufferedDownload(object, response.getOutputStream());
            long endBufferedDownloadTime = System.currentTimeMillis();
            assetRequest.getMetrics().addTime("BufferedDownloadTime",
                    endBufferedDownloadTime - startBufferedDownloadTime, SI.MILLI(SI.SECOND));
        }
        catch (IOException e) {
            log.warn("Download failure.", e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        } catch (StreamProcessException e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        } finally {
            IOUtils.closeQuietly(object);
        }
    }

    protected void doBufferedDownload(S3Object object,
                                      ServletOutputStream outputStream) throws StreamProcessException, IOException {
        final InputStream objectStream = object.getObjectContent();
        final ObjectMetadata metadata = object.getObjectMetadata();

        StreamProcessor buffer = createBuffer(metadata.getContentLength());

        try (ReadableByteChannel inChannel = Channels.newChannel(objectStream)) {
            buffer.processStream(inChannel, Channels.newChannel(outputStream));
        } catch (StreamProcessException e) {
            log.warn("Error streaming.", e);
            if(e.getProblem() == StreamProcessException.StreamProcessProblem.WRITER_ERROR) {
                //Problem was with downloading from S3, which makes this a 500
                throw e;
            }
        }
    }

    private StreamProcessor createBuffer(long size) {
        if (size > MAX_IN_MEMORY_BUFFER_SIZE) {
            return new DiskBuffer(executorService, DISK_BUFFER_CHUNK_SIZE);
        }
        else {
            return new MemoryBuffer(executorService, MEMORY_BUFFER_CHUNK_SIZE);
        }
    }

    protected void doHead(AccessibleServletRequest request,
                          AccessibleServletResponse response) throws ServletException, IOException {
        CAPSAssetRequest assetRequest = new CAPSAssetRequest(request, false, casCache, instanceRegion);

        AssetVersionMetadata assetMetadata = dynamoHelper.get(assetRequest);
        if (assetMetadata != null && !assetMetadata.isDeleted()
                && StringUtils.isNotEmpty(assetMetadata.getChecksum())) {

            response.setHeader("ETag",
                    String.format("\"%s\"", assetMetadata.getChecksum()));
            response.setHeader("Content-Length",
                    "" + assetMetadata.getFileSize());
            addCacheHeaders(assetRequest, response, assetMetadata.getTimestamp());
        }
        else {
            throw new AssetNotFoundException(request.toString());
        }
    }

    protected void doPost(AccessibleServletRequest request,
                          final AccessibleServletResponse response) throws ServletException, IOException {
        String method = request.getParameter("urlMethod");
        if (HttpMethod.DELETE.name().equalsIgnoreCase(method)) {
            doDelete(request, response);
        }
        else {
            final CAPSAssetRequest capsAssetRequest = new CAPSAssetRequest(request, casCache, instanceRegion);
            //Used by the MetricsFilter
            response.setAssetType(capsAssetRequest.getAssetType().getName());
            response.setMimeType(capsAssetRequest.getMediaType().getMimeType());
            response.setNamespace(capsAssetRequest.getAssetType().getNamespace());
            if (capsAssetRequest.shouldSetupMultipartUpload()) {
                setupMultipartUpload(capsAssetRequest);
                response.setStatus(HttpStatus.OK.value());
                addCORSHeaders(request, response);
                response.getWriter().write("{}");
                response.getWriter().flush();
            } else if (capsAssetRequest.shouldCompleteMultipartUpload()) {
                addCORSHeaders(request, response);
                Future<S3AssetMetadata> futureAssetMetadata = completeMultipartUpload(capsAssetRequest);
                //set the status as 202 instead of 200
                response.setStatus(HttpStatus.ACCEPTED.value());

                // We need to keep our client connection alive (with whitespace!) while we wait for 'complete' to complete...
                S3AssetMetadata assetMetadata = null;
                try {
                    Thread.sleep(ONE_SECOND);
                    while(! futureAssetMetadata.isDone()) {
                        Thread.sleep(FIVE_SECONDS);
                        response.getOutputStream().write(" ".getBytes());
                        response.getOutputStream().flush();
                    }
                    assetMetadata = futureAssetMetadata.get();
                }
                catch (InterruptedException e) {
                    response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
                    Thread.currentThread().interrupt();
                    return;
                }
                catch (ExecutionException e) {
                    if (e.getCause() instanceof IllegalStateException) {
                        throw (IllegalStateException)e.getCause();
                    } else {
                        log.info(String.format(
                                "Caught unknown exception while attempting to complete multipart upload: {ID: %s, AssetType: %s, AssetIndex: %s}",
                                capsAssetRequest.getId(), capsAssetRequest.getAssetType().getName(),
                                capsAssetRequest.getAssetIndex()));
                        if(e.getCause() instanceof RuntimeException) {
                            throw (RuntimeException)e.getCause();
                        }
                    }
                }

                populateResponseWithAssetMetadata(assetMetadata.getS3Length(), assetMetadata.getS3Checksum(), assetMetadata.getSSEVersionID(), response);
                response.setStatus(HttpStatus.OK.value());
            } else if (capsAssetRequest.shouldAbortMultipartUpload()) {
                abortMultipartUpload(capsAssetRequest);
                response.setStatus(HttpStatus.OK.value());
            } else {
                response.setStatus(HttpStatus.CREATED.value());
                setHttpAccessControl(request, response);
                doPut(capsAssetRequest, response);
            }
        }
    }

    protected void doOptions(AccessibleServletRequest request,
                             AccessibleServletResponse response) throws ServletException, IOException {
        response.setStatus(HttpStatus.OK.value());

        addCORSHeaders(request, response);

        response.getWriter().write("{}");
        response.getWriter().flush();
    }

    protected void addCORSHeaders(HttpServletRequest request, AccessibleServletResponse response) {
        if(request == null) {
            return;
        }
        String origin = request.getHeader("Origin");
        if(StringUtils.isNotBlank(origin)) {
            response.setHeader("Access-Control-Allow-Origin", origin);
        }
        response.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, HEAD");
        response.setHeader("Access-Control-Allow-Headers", "Origin, Content-Length, Content-MD5, Content-Type");
    }

    protected Map<String, Object> doPut(AccessibleServletRequest request,
                                        AccessibleServletResponse response) throws ServletException, IOException {
        CAPSAssetRequest capsAssetRequest = new CAPSAssetRequest(request, casCache, instanceRegion);
        return doPut(capsAssetRequest, response);
    }

    private Map<String, Object> doPut(CAPSAssetRequest assetRequest, AccessibleServletResponse response) throws ServletException, IOException {
        byte[] imageData = null;
        boolean deriveImage = false;
        AssetType assetType = assetRequest.getAssetType();

        log.info(String.format(
                "Operation:PUT, Context:{ID: %s, AssetType: %s, AssetIndex: %s, Content-Length: %s}",
                assetRequest.getId(), assetType.getName(),
                assetRequest.getAssetIndex(), assetRequest.getContentLength()));

        //Used by the metrics filter
        if (response != null) {
            response.setAssetType(assetType.getName());
            response.setMimeType(assetRequest.getMediaType().getMimeType());
            response.setNamespace(assetType.getNamespace());
        }

        addCORSHeaders(assetRequest.getOriginalRequest(), response);
        try {
            S3AssetMetadata assetMetadata;
            if (assetRequest.hasPart()) {
                assetMetadata = handleMultipartUpload(assetRequest, response);
                if (null == assetMetadata) {
                    return null;
                }
            }
            else {
                /**
                 * 1. Asset is not an image and doesn't require size validation
                 * 2. Asset is not an image and requires size validation
                 * 3. Asset is an image and does not require size validation
                 * 4. Asset is an image and requires size validation
                 * 5. Asset is an image and requires some stuff and size validation
                 * 6. Asset is an image and requires some stuff but not size validation
                 */
                boolean validateAssetSize = assetType.requiresSizeValidation() && !skipVerification(assetRequest);
                boolean modifyImage = assetType.requiresModification() && !assetRequest.getDisableMediaDerivation();
                boolean stripICCProfiles = assetType.getStripICCProfiles() && !assetRequest.getDisableMediaDerivation();
                boolean validateImage = assetType.requiresImageValidation() && !skipVerification(assetRequest);
                deriveImage = assetType.willDeriveChildren() && !assetRequest.getDisableMediaDerivation();

                UploadVerifier uploadVerifier = new UploadVerifier(assetType, assetRequest.getMediaType(), assetRequest.getMetrics());

                // Temporarily skip the media type validation if it's the internally generated request for derivations
                if(!skipVerification(assetRequest) && !assetRequest.isInternalDerivedAssetRequest()) {
                    uploadVerifier.verifyAssetMimeType();
                    if(uploadVerifier.shouldVerifyInputStreamFileSignature()) {
                        PushbackInputStream pushbackInputStream = new PushbackInputStream(assetRequest.getInputStream(), FileSignatureValidator.getMaxPushbackBuffer());
                        assetRequest.setInputStream(pushbackInputStream);
                        uploadVerifier.verifyFileSignature(pushbackInputStream);
                    }
                }

                if(assetRequest.getContentLength() <= 0) {
                    assetRequest.getMetrics().addCount("MissingContentLength_" + assetType.getName() + "_" + assetRequest.getAWSClient(), 1, Unit.ONE);
                }
                //Don't buffer the entire asset (image only) in memory if it violates size requirements
                else if (validateAssetSize) {
                    uploadVerifier.verifyAssetSize(assetRequest.getContentLength());
                }

                if(assetRequest.getMediaType().isImage()) {
                    if(validateImage || modifyImage || stripICCProfiles || deriveImage) {
                        imageData = IOUtils.toByteArray(assetRequest.getInputStream());
                        if(validateImage) {
                            uploadVerifier.verifyImage(imageData, fileValidator);
                        }

                        if(modifyImage || stripICCProfiles) {
                            imageData = handleImage(uploadVerifier, modifyImage, stripICCProfiles, validateAssetSize, imageData, assetType, assetRequest.getMediaType(), assetRequest.getId());
                            assetRequest.setContentLength((long)imageData.length);
                        }
                        assetRequest.setInputStream(new ByteArrayInputStream(imageData));
                    }
                }

                assetMetadata = performUpload(assetRequest);
            }

            Map<String, Object> responseObject = new HashMap<>();
            responseObject.put("Content-Length", assetMetadata.getOriginalLength());
            responseObject.put("ETag", "" + assetMetadata.getOriginalChecksum());
            String sseVersionID = ObjectUtils.toString(assetMetadata.getSSEVersionID());
            if(StringUtils.isNotEmpty(sseVersionID)) {
                responseObject.put("VersionID", sseVersionID);
            }
            responseObject.put("AssetType", assetType.getName());

            if (deriveImage) {
                if(imageData == null) {
                    throw new ImageDerivationException(String.format("ImageData lost for: {ID: %s, AssetType: %s}" + assetRequest.getId(), assetType.getName()));
                }
                List<Map<String, Object>> derivationResponses = deriveChildAssets(assetRequest, new ByteArrayInputStream(imageData));
                if(derivationResponses != null && !derivationResponses.isEmpty()) {
                    responseObject.put("Derivations", derivationResponses);
                }
            }

            if(!assetRequest.isInternalDerivedAssetRequest()) {
                response.setResponseLength(assetMetadata.getOriginalLength());
                response.setHeader("ETag", String.format("\"%s\"", assetMetadata.getOriginalChecksum()));

                //Used by the MetricsFilter
                response.setOriginalContentLength(assetMetadata.getOriginalLength());

                if(StringUtils.isNotEmpty(sseVersionID)) {
                    response.setHeader("VersionID", sseVersionID);
                }
                response.setHeader("Content-Type", "application/json");
                response.getOutputStream().write(OBJECT_MAPPER.writeValueAsString(responseObject).getBytes());

                if (StringUtils.isEmpty(assetMetadata.getS3Checksum())) {
                    response.setStatus(HttpServletResponse.SC_ACCEPTED);
                }

                if (responseObject.containsKey("Derivations")) {
                    response.setDerivationInformation((List<Map<String, Object>>) responseObject.get("Derivations"));
                }
            }

            return responseObject;
        }
        catch (NoSuchAlgorithmException e) {
            throw new ServletException("Checksum Calculation Exception", e);
        }
        catch (DataFormatException e) {
            throw new ServletException(e);
        }
        finally {
            IOUtils.closeQuietly(assetRequest.getInputStream());
        }
    }

    private byte[] handleImage(UploadVerifier uploadVerifier, boolean modifyImage, boolean stripICCProfiles, boolean validateAssetSize, byte[] imageData, AssetType assetType, MediaType mediaType, String requestId)
            throws IOException, DataFormatException {
        byte[] imageBuffer = null;
        if(modifyImage) {
            imageBuffer = UploadModifier.modifyImage(assetType, requestId, imageData);
        }
        else if(stripICCProfiles) {
            imageBuffer = UploadModifier.stripICCProfiles(assetType, mediaType, requestId, imageData);
        }

        if(validateAssetSize) {
            uploadVerifier.verifyAssetSize(imageBuffer.length);
        }
        return imageBuffer;
    }

    private S3AssetMetadata handleMultipartUpload(final CAPSAssetRequest assetRequest,
                                                  final AccessibleServletResponse response)
            throws NoSuchAlgorithmException, IOException, EndpointNotFoundException {
        try {
            return performMultipartUpload(assetRequest);
        } catch(IllegalStateException e) {
            final String badRequestMsg = Encode.forHtml(String.format("Request ID %s has been aborted. Please start over with a new multipart upload request",
                    assetRequest.getRequestId()));
            log.info(String.format("Bad request, sending following message to user: [%s]", badRequestMsg));
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getOutputStream().write(badRequestMsg.getBytes());
            response.getOutputStream().flush();
            return null;
        }
    }

    private List<Map<String, Object>> deriveChildAssets(CAPSAssetRequest request, InputStream stream) {
        String assetName = request.getAssetType().getName();
        AssetDeriver deriver = new AssetDeriver(casCache);
        Map<String, ZMEBufferedImage> childrenImages = null;

        try {
            childrenImages = deriver.deriveAll(assetName, new ZMEBufferedImage(stream));
        }
        catch (Exception e) {
            throw new ImageDerivationException(e);
        }
        finally {
            IOUtils.closeQuietly(stream);
        }

        Map<String, Exception> exceptions = deriver.getErrors();
        if(!exceptions.isEmpty()) {
            for(Map.Entry<String, Exception> entry : exceptions.entrySet()) {
                log.warn("Deriving image " + request.getId() + " of type " +
                        entry.getKey() + " failed", entry.getValue());
            }

            throw new ImageDerivationException("Failed to derive images from parent type " + assetName);
        }
        List<Map<String, Object>> derivations = new ArrayList<>();
        for(Map.Entry<String, ZMEBufferedImage> entry : childrenImages.entrySet()) {
            final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            ByteArrayInputStream childStream = null;

            try {
                float imageQuality = (float) casCache.getAssetType(entry.getKey()).getDerivationType().getQuality();
                entry.getValue().saveJPG(outputStream, imageQuality);
                byte[] array = outputStream.toByteArray();

                childStream = new ByteArrayInputStream(array);

                // Create Internal Child Request to mimic a real request.
                // IdType and Id should be the same as the parent for derived assets.
                CAPSAssetRequest childRequest = new CAPSAssetRequest(request.getId(), entry.getKey(),
                        request.getAssetIndex(), request.getAssetVersionId(), array.length, childStream,
                        request.getContentDisposition(), casCache.getMediaType("image/jpeg"), casCache, request.getDisableValidation(), instanceRegion, request.getMetrics());

                // Run another put with the child asset.
                Map<String, Object> response = doPut(childRequest, null);
                if(response != null) {
                    List<Map<String, Object>> children = (List<Map<String, Object>>)response.remove("Derivations");
                    derivations.add(response);
                    if(children != null) {
                        derivations.addAll(children);
                    }
                }
            }
            catch (Exception e) {
                throw new ImageDerivationException(e);
            }
            finally {
                IOUtils.closeQuietly(outputStream);
                IOUtils.closeQuietly(childStream);
            }
        }
        return derivations;
    }

    private void setHttpAccessControl(final AccessibleServletRequest request,
                                      final AccessibleServletResponse response) {
        final String origin = request.getHeader("Origin");
        if (origin != null && AMAZON_URL_PATTERN.matcher(origin).matches()) {
            response.setHeader("Access-Control-Allow-Origin", origin);
        }
    }

    private boolean skipVerification(CAPSAssetRequest request) {
        return request.getDisableValidation();
    }

    private void populateResponseWithAssetMetadata(final Long length, final String eTag,
                                                   final Long sseVersionID, final AccessibleServletResponse response)
            throws ServletException, IOException {
        response.setResponseLength(length);

        JSONObject responseObject = new JSONObject();
        try {
            responseObject.put("Content-Length", length);
            responseObject.put("ETag", "" + eTag);

            if(null != sseVersionID) {
                responseObject.put("VersionID", sseVersionID.toString());
            }
            response.setHeader("Content-Type", "application/json");
            response.getOutputStream().write(responseObject.toString().getBytes());
        }
        catch (JSONException e) {
            throw new ServletException(e);
        }
    }
}
