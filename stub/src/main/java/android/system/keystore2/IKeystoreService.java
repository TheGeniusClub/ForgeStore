package android.system.keystore2;

import android.os.IBinder;
import android.os.IInterface;

public interface IKeystoreService extends IInterface {
    String DESCRIPTOR = "android.system.keystore2.IKeystoreService";

    IKeystoreSecurityLevel getSecurityLevel(int securityLevel);
    KeyMetadata[] listEntries(int domain);
    KeyEntryResponse getKeyEntry(KeyDescriptor descriptor);
    void deleteKey(KeyDescriptor descriptor);

    class Stub {
        public static IKeystoreService asInterface(IBinder b) {
            throw new UnsupportedOperationException("STUB!");
        }
    }
}
