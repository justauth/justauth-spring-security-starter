package com.luoqiz.oauth2.justauth.web;

import com.luoqiz.oauth2.justauth.support.ConnectionData;
import com.luoqiz.oauth2.justauth.support.jdbc.JdbcUsersConnectionRepository;
import com.xkcoding.justauth.AuthRequestFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.Principal;
import java.util.List;

/**
 * 用户绑定管理
 */
@RestController
@RequestMapping("/connection")
public class JustauthController {

    @Autowired
    private AuthRequestFactory factory;

    @Autowired
    private JdbcUsersConnectionRepository jdbcUsersConnectionRepository;

    /**
     * 查看指定 providerId 的绑定记录
     * @param providerId
     * @param principal
     * @return
     * @throws IOException
     */
    @GetMapping("/bind/{providerId}")
    public ConnectionData bind(@PathVariable String providerId, Principal principal) throws IOException {
        if (principal != null) {
            return jdbcUsersConnectionRepository.findRowWithUserIdProviderId(principal.getName(), providerId);
        }
        return null;
    }

    /**
     * 解绑指定的 providerId 记录
     * @param providerId
     * @param principal
     * @return
     * @throws IOException
     */
    @DeleteMapping("/bind/{providerId}")
    public boolean unBind(@PathVariable String providerId, Principal principal) throws IOException {
        if (principal != null) {
            return jdbcUsersConnectionRepository.removeConnections(providerId, principal.getName());
        }
        return false;
    }

    /**
     * 查看当前用户已绑定的所有记录
     * @param principal
     * @return
     * @throws IOException
     */
    @GetMapping("/bind/list")
    public List<ConnectionData> bind(Principal principal) throws IOException {
        return jdbcUsersConnectionRepository.findUserWithUserId(principal.getName());
    }


}
