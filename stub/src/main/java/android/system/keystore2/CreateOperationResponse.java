package android.system.keystore2;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;

public class CreateOperationResponse implements Parcelable {
    public IKeystoreOperation iOperation;
    public OperationChallenge operationChallenge;
    public KeyParameters parameters;

    public static final Creator<CreateOperationResponse> CREATOR = new Creator<>() {
        public CreateOperationResponse createFromParcel(Parcel in) {
            CreateOperationResponse r = new CreateOperationResponse();
            int sz = in.readInt();
            if (sz > 0) {
                IBinder b = in.readStrongBinder();
                r.iOperation = IKeystoreOperation.Stub.asInterface(b);
            }
            int hasChallenge = in.readInt();
            if (hasChallenge != 0) {
                r.operationChallenge = OperationChallenge.CREATOR.createFromParcel(in);
            }
            return r;
        }
        public CreateOperationResponse[] newArray(int size) {
            return new CreateOperationResponse[size];
        }
    };

    @Override
    public int describeContents() { return 0; }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(iOperation != null ? 1 : 0);
        if (iOperation != null) dest.writeStrongBinder(iOperation.asBinder());
        dest.writeInt(operationChallenge != null ? 1 : 0);
        if (operationChallenge != null) operationChallenge.writeToParcel(dest, flags);
    }
}
