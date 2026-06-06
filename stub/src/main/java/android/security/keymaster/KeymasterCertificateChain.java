package android.security.keymaster;

import java.util.ArrayList;
import java.util.List;

public class KeymasterCertificateChain {
    public List<byte[]> chain;

    public KeymasterCertificateChain() {
        chain = new ArrayList<>();
    }

    public KeymasterCertificateChain(List<byte[]> chain) {
        this.chain = chain;
    }
}
