package cn.porsche.keycloak.phone;

import cn.porsche.keycloak.phone.util.JsonUtil;
import com.google.common.collect.Lists;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;

public class PhoneAuthenticator implements Authenticator {

  private static Logger logger = Logger.getLogger(PhoneAuthenticator.class);

  private KeycloakSession session;

  public PhoneAuthenticator(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    String phone = retrievePhone(context);
    String code = retrieveCode(context);
    // 参数校验

    // 使用手机号查询用户
    List<UserModel> userModelList = context.getSession().userStorageManager().searchForUserByUserAttribute(
        getPropertyValue(context, PhoneAuthenticatorFactory.PROPERTY_USER_ATTRIBUTE_PHONE),
        retrievePhone(context), context.getRealm());
    if (userModelList.size() > 0) {
      // 用户存在，校验手机验证码
      try {
        doSMSAuthenticate(context, phone, code);
        context.setUser(userModelList.get(0));
        context.success();
      } catch (RuntimeException e) {
        Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_request_runtime", e.getMessage());
        context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
      } catch (IOException e) {
        Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_request_IO", e.getMessage());
        context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
      }
    } else {
      // 用户不存在
      Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_request", "Invalid user credentials");
      context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
    }
  }

  private String retrievePhone(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
    return inputData.getFirst(getPropertyValue(context, PhoneAuthenticatorFactory.PROPERTY_FORM_PHONE));
  }

  private String retrieveCode(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
    return inputData.getFirst(getPropertyValue(context, PhoneAuthenticatorFactory.PROPERTY_FORM_CODE));
  }

  private Response errorResponse(int status, String error, String errorDescription) {
    OAuth2ErrorRepresentation errorRep = new OAuth2ErrorRepresentation(error, errorDescription);
    return Response.status(status).entity(errorRep).type(MediaType.APPLICATION_JSON_TYPE).build();
  }

  private String getPropertyValue(AuthenticationFlowContext context, String key) {
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    return config.getConfig().get(key);
  }

  private void doSMSAuthenticate(AuthenticationFlowContext context, String phone, String code)
      throws IOException {
    String requestUrl = getPropertyValue(context, PhoneAuthenticatorFactory.PROPERTY_SMS_REQUEST_URL);
    String requestMethod = getPropertyValue(context, PhoneAuthenticatorFactory.PROPERTY_SMS_REQUEST_METHOD);

    HttpClient client = HttpClients.createDefault();
    Map<String, Object> requestParam = buildRequestParam(context, phone, code);

    HttpResponse response = null;
    if ("get".equals(requestMethod)) {
      HttpGet httpGet = new HttpGet(requestUrl + buildGetParam());
      response = client.execute(httpGet);
    } else if ("post.form".equals(requestMethod) || "post.json".equals(requestMethod)) {
      HttpPost httpPost = new HttpPost(requestUrl);
      if ("post.form".equals(requestMethod)) {
        httpPost.addHeader("Content-Type", "application/x-www-form-urlencode");
        List<NameValuePair> nameValuePairList = Lists.newArrayList();
        requestParam.forEach((key, value) -> nameValuePairList.add(new BasicNameValuePair(key, value.toString())));
        httpPost.setEntity(new UrlEncodedFormEntity(nameValuePairList, "utf-8"));
      } else {
        httpPost.addHeader("Content-Type", "application/json");
        httpPost.setEntity(new StringEntity(JsonUtil.toString(requestParam)));
      }
      response = client.execute(httpPost);
    } else {
      throw new RuntimeException("invalid request method, please check authentication config");
    }

    String checkKey = getPropertyValue(context, PhoneAuthenticatorFactory.PROPERTY_SMS_RESPONSE_CHECK_KEY);
    String checkValue = getPropertyValue(context, PhoneAuthenticatorFactory.PROPERTY_SMS_RESPONSE_CHECK_VALUE);

    if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
      Map<String, Object> responseData = JsonUtil.parseObject(EntityUtils.toString(response.getEntity()), Map.class);
      String[] keyArray = checkKey.split("\\.");
      Object value = responseData;
      for (String key : keyArray) {
        if (value instanceof Map) {
          value = ((Map<String, Object>) value).get(key);
        }
      }

      if ((value instanceof String && checkValue.equals(value)) ||
          (value instanceof Integer && Integer.parseInt(checkValue) == (Integer) value) ||
          (value instanceof Boolean && Boolean.valueOf(checkValue) == value)) {
        return;
      }
    }
    throw new RuntimeException("check phone code fail");
  }

  private Map<String, Object> buildRequestParam(AuthenticationFlowContext context, String phone, String code) {
    String requestParamDefault = getPropertyValue(context, PhoneAuthenticatorFactory.PROPERTY_SMS_REQUEST_PARAM_DEFAULT);
    String requestParamPhone = getPropertyValue(context, PhoneAuthenticatorFactory.PROPERTY_SMS_REQUEST_PARAM_PHONE);
    String requestParamCode = getPropertyValue(context, PhoneAuthenticatorFactory.PROPERTY_SMS_REQUEST_PARAM_CODE);

    Map<String, Object> requestParam = JsonUtil.parseObject(requestParamDefault, Map.class);
    requestParam.put(requestParamPhone, phone);
    requestParam.put(requestParamCode, code);
    return requestParam;
  }

  private String buildGetParam() {
    return "";
  }

  @Override
  public void action(AuthenticationFlowContext context) {
  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
  }

  @Override
  public void close() {
  }
}
