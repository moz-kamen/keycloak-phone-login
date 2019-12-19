package cn.porsche.keycloak.phone;

import com.google.common.collect.Lists;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class PhoneAuthenticatorFactory implements AuthenticatorFactory {

  public static final String PROVIDER_ID = "sms-login-authentication";
  public static final String PROVIDER_TYPE = "SMS Login";

  private static Logger logger = Logger.getLogger(PhoneAuthenticatorFactory.class);

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    return new PhoneAuthenticator(session);
  }

  public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
      AuthenticationExecutionModel.Requirement.REQUIRED,
      AuthenticationExecutionModel.Requirement.DISABLED
  };

  @Override
  public Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public String getDisplayType() {
    return PROVIDER_TYPE;
  }

  @Override
  public String getReferenceCategory() {
    return PROVIDER_TYPE;
  }

  @Override
  public String getHelpText() {
    return "短信验证登录校验器";
  }

  @Override
  public boolean isUserSetupAllowed() {
    return true;
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  public static final String PROPERTY_USER_ATTRIBUTE_PHONE = "user.attribute.phone";
  public static final String PROPERTY_FORM_PHONE = "form.phone";
  public static final String PROPERTY_FORM_CODE = "form.code";
  public static final String PROPERTY_SMS_REQUEST_URL = "sms.request.url";
  public static final String PROPERTY_SMS_REQUEST_METHOD = "sms.request.method";
  public static final String PROPERTY_SMS_REQUEST_PARAM_DEFAULT = "sms.request.param.default";
  public static final String PROPERTY_SMS_REQUEST_PARAM_PHONE = "sms.request.param.phone";
  public static final String PROPERTY_SMS_REQUEST_PARAM_CODE = "sms.request.param.code";
  public static final String PROPERTY_SMS_RESPONSE_CHECK_KEY = "sms.response.check.key";
  public static final String PROPERTY_SMS_RESPONSE_CHECK_VALUE = "sms.response.check.value";

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    List<ProviderConfigProperty> propertyList = Lists.newArrayList();
    // 用户属性
    propertyList.add(new ProviderConfigProperty(
      PROPERTY_USER_ATTRIBUTE_PHONE, "user attribute key - phone", "用户属性键名称[手机号]", ProviderConfigProperty.STRING_TYPE, "phone"
    ));
    // 登陆表单
    propertyList.add(new ProviderConfigProperty(
      PROPERTY_FORM_PHONE, "login form key - phone", "登录表单键名称[手机号]", ProviderConfigProperty.STRING_TYPE, "phone"
    ));
    propertyList.add(new ProviderConfigProperty(
      PROPERTY_FORM_CODE, "login form key - code", "登陆表单键名称[验证码]", ProviderConfigProperty.STRING_TYPE, "code"
    ));
    // 短信服务接口
    propertyList.add(new ProviderConfigProperty(
      PROPERTY_SMS_REQUEST_URL, "sms request url", "SMS校验接口地址", ProviderConfigProperty.STRING_TYPE, "https://"
    ));
    propertyList.add(new ProviderConfigProperty(
      PROPERTY_SMS_REQUEST_METHOD, "sms request method", "SMS校验接口请求类型[get|post.form|post.json]", ProviderConfigProperty.STRING_TYPE, "post.json"
    ));
    // 短信接口请求参数
    propertyList.add(new ProviderConfigProperty(
      PROPERTY_SMS_REQUEST_PARAM_DEFAULT, "sms request param - default", "SMS校验默认参数", ProviderConfigProperty.STRING_TYPE, "{}"
    ));
    propertyList.add(new ProviderConfigProperty(
      PROPERTY_SMS_REQUEST_PARAM_PHONE, "sms request param - phone", "SMS校验手机号参数名", ProviderConfigProperty.STRING_TYPE, "phone"
    ));
    propertyList.add(new ProviderConfigProperty(
      PROPERTY_SMS_REQUEST_PARAM_CODE, "sms request param - code", "SMS校验验证码参数名", ProviderConfigProperty.STRING_TYPE, "code"
    ));
    // 短信接口响应结果
    propertyList.add(new ProviderConfigProperty(
      PROPERTY_SMS_RESPONSE_CHECK_KEY, "sms response check - key", "SMS校验结果确认键", ProviderConfigProperty.STRING_TYPE, "phone"
    ));
    propertyList.add(new ProviderConfigProperty(
      PROPERTY_SMS_RESPONSE_CHECK_VALUE, "sms response check - value", "SMS校验结果确认值", ProviderConfigProperty.STRING_TYPE, "true"
    ));

    return propertyList;
  }

  @Override
  public void init(Scope scope) {
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
  }

  @Override
  public void close() {
  }
}
