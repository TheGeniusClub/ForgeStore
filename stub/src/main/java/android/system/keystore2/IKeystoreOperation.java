package android.system.keystore2;

import android.os.Binder;
import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;

public interface IKeystoreOperation extends IInterface {
    String DESCRIPTOR = "android.system.keystore2.IKeystoreOperation";

    byte[] finish(byte[] input, byte[] signature) throws RemoteException;
    void updateAad(byte[] input) throws RemoteException;
    byte[] update(byte[] input) throws RemoteException;
    void abort() throws RemoteException;

    abstract class Stub extends Binder implements IKeystoreOperation {
        public static IKeystoreOperation asInterface(IBinder b) {
            throw new UnsupportedOperationException("STUB!");
        }

        @Override
        public IBinder asBinder() {
            return this;
        }
    }
}
