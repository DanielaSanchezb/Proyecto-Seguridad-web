package com.api.gestion.service.impl;

import com.api.gestion.constantes.FacturaConstantes;
import com.api.gestion.dao.UserDAO;
import com.api.gestion.pojo.User;
import com.api.gestion.security.CustomerDetailservice;
import com.api.gestion.security.jwt.JwtUtil;
import com.api.gestion.service.UserService;
import com.api.gestion.util.FacturaUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Objects;

@Slf4j
@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserDAO userDAO;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private CustomerDetailservice customerDetailservice;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public ResponseEntity<String> signUp(Map<String, String> requestMap) {
        log.info("Registro interno de un usaurio {}", requestMap);
        try{
            if (validateSignUpMap(requestMap)){
                User user =userDAO.findByEmail(requestMap.get("email"));
                //Si el objeto es null, no existe
                if(Objects.isNull(user)){
                    userDAO.save(getUserFromMap(requestMap));
                    return  FacturaUtils.getResponseEntity("Usuario registrado con exito", HttpStatus.CREATED );
                }
                else {
                    return FacturaUtils.getResponseEntity("El usuario con ese email ya existe", HttpStatus.BAD_REQUEST);
                }
            }
            else {
                return FacturaUtils.getResponseEntity(FacturaConstantes.INVALID_DATA, HttpStatus.BAD_REQUEST);
            }
        } catch (Exception exception){
            exception.printStackTrace();
        }
        return FacturaUtils.getResponseEntity(FacturaConstantes.SOMETHING_WENT_WRONG, HttpStatus.INTERNAL_SERVER_ERROR );
    }

    @Override
    public ResponseEntity<String> login(Map<String, String> requestMap) {
        log.info("Dentro de login");
        try{
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(requestMap.get("email"),requestMap.get("password"))
            );
            if(authentication.isAuthenticated()){
                if(customerDetailservice.getUserDetail().getStatus().equalsIgnoreCase("true")){
                    return new ResponseEntity<String>("{\"token\":\"" + jwtUtil.generateToken(customerDetailservice.getUserDetail().getEmail() , customerDetailservice.getUserDetail().getRole()) + "\"}",
                            HttpStatus.OK);
                }
                else{
                    return new ResponseEntity<String>("{\"mensaje\":\""+" Espere la aprobación del administrador "+"\"}", HttpStatus.BAD_REQUEST);
                }
            }
        }catch (Exception exception){
            log.error("{}", exception);
        }
        return new ResponseEntity<String>("{\"mensaje\":\""+" Credenciales incorrectas "+"\"}", HttpStatus.BAD_REQUEST);
    }

    private Boolean validateSignUpMap(Map<String, String> requestMap){
        if(requestMap.containsKey("nombre") && requestMap.containsKey("numeroDeContacto") && requestMap.containsKey("email") && requestMap.containsKey("password")){
            return true;
        }
        return false;
    }
    private User getUserFromMap(Map<String, String> requestMap){
        User user = new User();
        user.setNombre(requestMap.get("nombre"));
        user.setNumeroDeContacto(requestMap.get("numeroDeContacto"));
        user.setEmail(requestMap.get("email"));
        user.setPassword(requestMap.get("password"));
        user.setStatus("false");
        user.setRole("user");
        return user;
    }
}
