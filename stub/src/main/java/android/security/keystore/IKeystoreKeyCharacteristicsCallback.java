package android.security.keystore;

import android.os.IBinder;
import android.os.RemoteException;
import android.security.keymaster.KeyCharacteristics;

public interface IKeystoreKeyCharacteristicsCallback {
    void onFinished(KeystoreResponse response, KeyCharacteristics characteristics) throws RemoteException;

    abstract class Stub {
        public static IKeystoreKeyCharacteristicsCallback asInterface(IBinder b) {
            throw new UnsupportedOperationException("STUB!");
        }
    }
}
