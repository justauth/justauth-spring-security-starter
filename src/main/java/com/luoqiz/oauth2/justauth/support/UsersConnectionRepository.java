package com.luoqiz.oauth2.justauth.support;

import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;

public interface UsersConnectionRepository {
    List<String> findUserIdsWithProvider(String providerId, String providerUserId);

    Set<String> findUserIdsConnectedTo(String providerId, Set<String> providerUserIds);

    ConnectionData findRowWithUserIdProviderId(String userId, String providerId);

    @Transactional
    void addConnection(ConnectionData connectionData);

    @Transactional
    void updateConnection(ConnectionData data);

    @Transactional
    boolean removeConnections(String providerId, String userId);

    List<ConnectionData> findUserWithUserId(String userId);
}
