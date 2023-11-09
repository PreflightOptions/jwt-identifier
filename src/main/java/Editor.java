import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Map;

public class Editor implements ExtensionProvidedHttpRequestEditor {
    MontoyaApi api;
    EditorCreationContext creationContext;
    private final RawEditor requestEditor;
    private HttpRequestResponse requestResponse;
    private String test = "init";
    private DecodedJWT decodedJwt;

    public Editor(MontoyaApi api, EditorCreationContext creationContext) {
        this.api = api;
        this.creationContext = creationContext;
        requestEditor = api.userInterface().createRawEditor(EditorOptions.READ_ONLY);
        //if (creationContext.editorMode() == EditorMode.READ_ONLY);
//        {
//            requestEditor = api.userInterface().createRawEditor(EditorOptions.READ_ONLY);
//        }
//        else {
//            requestEditor = api.userInterface().createRawEditor();
//        }
    }

    @Override
    public HttpRequest getRequest() {
        return requestResponse.request();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Map<String, Claim> claims = decodedJwt.getClaims();

        String exp = "Expires: " + decodedJwt.getExpiresAt() + "\r\n";
        String iss = "Issued: " + decodedJwt.getIssuedAt() + "\r\n";
        String prefix = "\r\n======= Claims =======\r\n";
        try {
            outputStream.write((exp + iss + prefix).getBytes());
        } catch (IOException e) {
            api.logging().logToError(e.toString());
        }

        claims.forEach((s, claim) -> {
            String a = s + ": " + claim.toString() + "\r\n";
            try {
                outputStream.write(a.getBytes());
            } catch (IOException e) {
                api.logging().logToError(e.toString());
            }
        });
        byte[] bytes = outputStream.toByteArray();
        this.requestEditor.setContents(ByteArray.byteArray(bytes));
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        try {
            if(requestResponse.request().hasHeader("Authorization")) {
                HttpHeader h = requestResponse.request().header("Authorization");
                String encodedJWT = h.value().split("\s")[1];
                this.decodedJwt = JWT.decode(encodedJWT);

                this.test = this.decodedJwt.getSubject();

                return true;
            }
        } catch (Exception e) {
            return false;
        }

        return false;
    }

    @Override
    public String caption() {
        return test;
    }

    @Override
    public Component uiComponent() {
        return requestEditor.uiComponent();
    }

    @Override
    public Selection selectedData() {
        return requestEditor.selection().isPresent() ? requestEditor.selection().get() : null;
    }

    @Override
    public boolean isModified() {
        return requestEditor.isModified();
    }
}
