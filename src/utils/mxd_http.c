#include "mxd_http.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    mxd_http_response_t* resp = (mxd_http_response_t*)userp;
    
    char* ptr = realloc(resp->data, resp->size + realsize + 1);
    if (!ptr) {
        return 0;  // Out of memory
    }
    resp->data = ptr;
    memcpy(&(resp->data[resp->size]), contents, realsize);
    resp->size += realsize;
    resp->data[resp->size] = 0;
    
    return realsize;
}

mxd_http_response_t* mxd_http_get(const char* url) {
    CURL* curl = curl_easy_init();
    mxd_http_response_t* response = calloc(1, sizeof(mxd_http_response_t));
    if (!response) {
        return NULL;
    }
    
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            response->status_code = -1;
        } else {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            response->status_code = (int)http_code;
        }
        curl_easy_cleanup(curl);
    } else {
        free(response);
        return NULL;
    }
    
    return response;
}

mxd_http_response_t* mxd_http_post(const char* url, const char* data, const char* content_type) {
    CURL* curl = curl_easy_init();
    mxd_http_response_t* response = calloc(1, sizeof(mxd_http_response_t));
    if (!response) {
        return NULL;
    }
    
    if (curl) {
        struct curl_slist* headers = NULL;
        
        if (content_type) {
            char header[256];
            snprintf(header, sizeof(header), "Content-Type: %s", content_type);
            headers = curl_slist_append(headers, header);
        }
        
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        
        if (headers) {
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        }
        
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            response->status_code = -1;
        } else {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            response->status_code = (int)http_code;
        }
        
        if (headers) {
            curl_slist_free_all(headers);
        }
        curl_easy_cleanup(curl);
    } else {
        free(response);
        return NULL;
    }
    
    return response;
}

void mxd_http_free_response(mxd_http_response_t* response) {
    if (response) {
        free(response->data);
        free(response);
    }
}
