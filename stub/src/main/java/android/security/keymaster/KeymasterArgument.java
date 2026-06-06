package android.security.keymaster;

import android.os.Parcel;
import android.os.Parcelable;

public class KeymasterArgument implements Parcelable {
    @Override
    public void writeToParcel(Parcel dest, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }

    @Override
    public int describeContents() {
        throw new UnsupportedOperationException("STUB!");
    }

    public static final Creator<KeymasterArgument> CREATOR = new Creator<KeymasterArgument>() {
        @Override
        public KeymasterArgument createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }
        @Override
        public KeymasterArgument[] newArray(int size) {
            return new KeymasterArgument[size];
        }
    };
}
