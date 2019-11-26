package com.luoqiz.oauth2.justauth.support.jdbc;

import com.luoqiz.oauth2.justauth.support.ConnectionData;
import com.luoqiz.oauth2.justauth.support.UsersConnectionRepository;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.ResultSetExtractor;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.transaction.annotation.Transactional;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;

/**
 * 认证来源，目前只实现保存在数据库中的用户
 */
public class JdbcUsersConnectionRepository implements UsersConnectionRepository {

    private final JdbcTemplate jdbcTemplate;

    private final TextEncryptor textEncryptor;

    private String tablePrefix = "";

    public JdbcUsersConnectionRepository(DataSource dataSource, TextEncryptor textEncryptor) {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
        if (textEncryptor != null) {
            this.textEncryptor = textEncryptor;
        } else {
            this.textEncryptor = Encryptors.noOpText();
        }

    }


    /**
     * Sets a table name prefix. This will be prefixed to all the table names before queries are executed. Defaults to "".
     * This is can be used to qualify the table name with a schema or to distinguish Spring Social tables from other application tables.
     *
     * @param tablePrefix the tablePrefix to set
     */
    public void setTablePrefix(String tablePrefix) {
        this.tablePrefix = tablePrefix;
    }

    @Override
    public List<String> findUserIdsWithProvider(String providerId, String providerUserId) {
        List<String> localUserIds = jdbcTemplate.queryForList("select userId from " + tablePrefix + "UserConnection where providerId = ? and providerUserId = ?", String.class, providerId, providerUserId);
//        if (localUserIds.size() == 0 ) {
//            String newUserId = connectionSignUp.execute(connection);
//            if (newUserId != null) {
//                createConnectionRepository(newUserId).addConnection(connection);
//                return Arrays.asList(newUserId);
//            }
//        }
        return localUserIds;
    }
    @Override
    public Set<String> findUserIdsConnectedTo(String providerId, Set<String> providerUserIds) {
        MapSqlParameterSource parameters = new MapSqlParameterSource();
        parameters.addValue("providerId", providerId);
        parameters.addValue("providerUserIds", providerUserIds);
        final Set<String> localUserIds = new HashSet<String>();
        return new NamedParameterJdbcTemplate(jdbcTemplate).query("select userId from " + tablePrefix + "UserConnection where providerId = :providerId and providerUserId in (:providerUserIds)", parameters,
                new ResultSetExtractor<Set<String>>() {
                    public Set<String> extractData(ResultSet rs) throws SQLException, DataAccessException {
                        while (rs.next()) {
                            localUserIds.add(rs.getString("userId"));
                        }
                        return localUserIds;
                    }
                });
    }
    @Override
    public ConnectionData findRowWithUserIdProviderId(String userId, String providerId) {
        RowMapper<ConnectionData> rm = new BeanPropertyRowMapper<ConnectionData>(ConnectionData.class);
        return jdbcTemplate.queryForObject("select * from " + tablePrefix + "UserConnection where userId = ? and providerId = ?",
                new Object[]{userId, providerId}, new RowMapper<ConnectionData>() {
                    @Override
                    public ConnectionData mapRow(ResultSet resultSet, int i) throws SQLException {
                        return new ConnectionData(resultSet.getString("userId"),
                                resultSet.getString("providerId"),
                                resultSet.getString("providerUserId"),
                                resultSet.getString("displayName"),
                                resultSet.getString("profileUrl"),
                                resultSet.getString("imageUrl"),
                                resultSet.getString("accessToken"),
                                resultSet.getString("secret"),
                                resultSet.getString("refreshToken"),
                                resultSet.getLong("expireTime")
                        );
                    }
                });
    }

    @Override
    @Transactional
    public void addConnection(ConnectionData connectionData) {
        try {
            int rank = jdbcTemplate.queryForObject("select coalesce(max(rank) + 1, 1) as rank from " + tablePrefix + "UserConnection where userId = ? and providerId = ?", new Object[]{connectionData.getUserId(), connectionData.getProviderId()}, Integer.class);
            jdbcTemplate.update("insert into " + tablePrefix + "UserConnection (userId, providerId, providerUserId, rank, displayName, profileUrl, imageUrl, accessToken, secret, refreshToken, expireTime) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    connectionData.getUserId(), connectionData.getProviderId(), connectionData.getProviderUserId(),
                    rank, connectionData.getDisplayName(), connectionData.getProfileUrl(),
                    connectionData.getImageUrl(), encrypt(connectionData.getAccessToken()),
                    encrypt(connectionData.getSecret()), encrypt(connectionData.getRefreshToken()), connectionData.getExpireTime());
        } catch (DuplicateKeyException e) {
            throw new DuplicateKeyException(connectionData.getUserId());
        }
    }

    @Override
    @Transactional
    public void updateConnection(ConnectionData data) {
        jdbcTemplate.update("update " + tablePrefix + "UserConnection set displayName = ?, profileUrl = ?, imageUrl = ?, accessToken = ?, secret = ?, refreshToken = ?, expireTime = ? where userId = ? and providerId = ? and providerUserId = ?",
                data.getDisplayName(), data.getProfileUrl(), data.getImageUrl(), encrypt(data.getAccessToken()),
                encrypt(data.getSecret()), encrypt(data.getRefreshToken()), data.getExpireTime(),
                data.getUserId(), data.getProviderId(), data.getProviderUserId());
    }

    @Override
    @Transactional
    public boolean removeConnections(String providerId, String userId) {
        return jdbcTemplate.update("delete from " + tablePrefix + "UserConnection where userId = ? and providerId = ?",
                userId, providerId) == 1;
    }

//    @Transactional
//    public void removeConnection(ConnectionKey connectionKey) {
//        jdbcTemplate.update("delete from " + tablePrefix + "UserConnection where userId = ? and providerId = ? and providerUserId = ?", userId, connectionKey.getProviderId(), connectionKey.getProviderUserId());
//    }

    // internal helpers

    private String selectFromUserConnection() {
        return "select userId, providerId, providerUserId, displayName, profileUrl, imageUrl, accessToken, secret, refreshToken, expireTime from " + tablePrefix + "UserConnection";
    }

//    private Connection<?> findPrimaryConnection(String providerId) {
//        List<Connection<?>> connections = jdbcTemplate.query(selectFromUserConnection() + " where userId = ? and providerId = ? order by rank", connectionMapper, userId, providerId);
//        if (connections.size() > 0) {
//            return connections.get(0);
//        } else {
//            return null;
//        }
//    }

    private String encrypt(String text) {
        return text != null ? textEncryptor.encrypt(text) : text;
    }

    @Override
    public List<ConnectionData> findUserWithUserId(String userId) {
        List<Map<String, Object>> result = jdbcTemplate.queryForList("select * from " + tablePrefix + "UserConnection where userId = ? ",
                new Object[]{userId});
        List<ConnectionData> rs = new ArrayList<>();
        result.forEach(resultSet -> {
            ConnectionData connection = new ConnectionData(
                    (String) resultSet.get("userId"),
                    (String) resultSet.get("providerId"),
                    (String) resultSet.get("providerUserId"),
                    (String) resultSet.get("displayName"),
                    (String) resultSet.get("profileUrl"),
                    (String) resultSet.get("imageUrl"),
                    (String) resultSet.get("accessToken"),
                    (String) resultSet.get("secret"),
                    (String) resultSet.get("refreshToken"),
                    (Long) resultSet.get("expireTime")
            );
            rs.add(connection);
        });
        return rs;
    }
}
