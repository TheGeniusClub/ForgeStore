package android.security.keystore;

import android.os.Parcel;
import android.os.Parcelable;

public class KeystoreResponse implements Parcelable {
    public final int error_code_;
    public final String error_msg_;

    protected KeystoreResponse(int errorCode, String errorMsg) {
        error_code_ = errorCode;
        error_msg_ = errorMsg;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }

    @Override
    public int describeContents() {
        throw new UnsupportedOperationException("STUB!");
    }

    public static final Creator<KeystoreResponse> CREATOR = new Creator<KeystoreResponse>() {
        @Override
        public KeystoreResponse createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }
        @Override
        public KeystoreResponse[] newArray(int size) {
            return new KeystoreResponse[size];
        }
    };
}
