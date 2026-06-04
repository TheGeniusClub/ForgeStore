package android.hardware.security.keymint;

import android.os.Parcel;
import android.os.Parcelable;

public class KeyParameter implements Parcelable {
    public int tag = 0;
    public KeyParameterValue value;

    public static final Parcelable.Creator<KeyParameter> CREATOR =
            new Parcelable.Creator<>() {
                public KeyParameter createFromParcel(Parcel in) {
                    throw new UnsupportedOperationException("STUB!");
                }
                public KeyParameter[] newArray(int size) {
                    throw new UnsupportedOperationException("STUB!");
                }
            };

    @Override
    public int describeContents() { throw new UnsupportedOperationException("STUB!"); }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }
}
