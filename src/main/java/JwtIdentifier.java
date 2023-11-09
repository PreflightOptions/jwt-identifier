import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class JwtIdentifier implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("JWT Identifier");

        api.userInterface().registerHttpRequestEditorProvider(new EditorProvider(api));
    }
}
