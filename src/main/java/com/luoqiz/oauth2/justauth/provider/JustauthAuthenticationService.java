package com.luoqiz.oauth2.justauth.provider;

import com.luoqiz.oauth2.justauth.JustauthAuthenticationToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * JustauthAuthenticationService 服务标准接口
 * @param <S>
 */
public interface JustauthAuthenticationService<S> {

    enum ConnectionCardinality {
        /**
         * only one connected providerUserId per userId and vice versa
         */
        ONE_TO_ONE(false, false),

        /**
         * many connected providerUserIds per userId, but only one userId per providerUserId
         */
        ONE_TO_MANY(false, true),

        /**
         * only one providerUserId per userId, but many userIds per providerUserId.
         * Authentication of users not possible
         */
        MANY_TO_ONE(true, false),

        /**
         * no restrictions. Authentication of users not possible
         */
        MANY_TO_MANY(true, true);

        private final boolean multiUserId;
        private final boolean multiProviderUserId;

        private ConnectionCardinality(boolean multiUserId, boolean multiProviderUserId) {
            this.multiUserId = multiUserId;
            this.multiProviderUserId = multiProviderUserId;
        }

        /**
         * allow many userIds per providerUserId. If true, authentication is not possible
         *
         * @return true if multiple local users are allowed per provider user ID
         */
        public boolean isMultiUserId() {
            return multiUserId;
        }

        /**
         * allow many providerUserIds per userId
         *
         * @return true if users are allowed multiple connections to a provider
         */
        public boolean isMultiProviderUserId() {
            return multiProviderUserId;
        }

        public boolean isAuthenticatePossible() {
            return !isMultiUserId();
        }
    }

    JustauthAuthenticationToken getAuthToken(HttpServletRequest request, HttpServletResponse response);

}
