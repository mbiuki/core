package com.dotcms.security.multipartrequest;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.dotcms.filters.interceptor.Result;
import com.dotcms.filters.interceptor.WebInterceptor;
import com.dotmarketing.util.Config;
import com.dotmarketing.util.UtilMethods;

/**
 * This web interceptor checks if the current request is a POST or PUT and multipart
 * If it is, check if the filename does not contains any malicious code
 * @author jsanca
 */
public class MultiPartRequestSecurityWebInterceptor implements WebInterceptor {

    private final String[] filterPatterns;
    private final long cacheToDiskSize;

    public MultiPartRequestSecurityWebInterceptor() {
        filterPatterns = Config.getStringArrayProperty("MULTIPART_REQUEST_SECURITY_FILTER_PATTERNS", new String[]{"/*"});
        cacheToDiskSize = Config.getLongProperty("MULTIPART_REQUEST_SECURITY_CACHE_TO_DISK_SIZE", 1024*1000*50);
        
    }

    @Override
    public String[] getFilters() {
        return filterPatterns;
    }

    @Override
    public Result intercept(final HttpServletRequest request,
                            final HttpServletResponse response) throws IOException {

        final String method = request.getMethod();

        if ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method)) {

            final String contentTypeHeader = request.getHeader("content-type");
            if (UtilMethods.isSet(contentTypeHeader) && contentTypeHeader.toLowerCase().contains("multipart/form-data")) {

                final MultiPartSecurityRequestWrapper requestWrapper = new MultiPartSecurityRequestWrapper(request, cacheToDiskSize);


                return new Result.Builder().wrap(requestWrapper).next().build();
            }
        }

        return Result.NEXT;
    }


    
    
}
