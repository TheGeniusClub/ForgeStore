package android.system.keystore2;

import android.hardware.security.keymint.KeyParameter;
import android.os.Parcel;
import android.os.Parcelable;

public class Authorization implements Parcelable {
    public KeyParameter keyParameter;
    public int securityLevel;

    public static final Parcelable.Creator<Authorization> CREATOR =
            new Parcelable.Creator<>() {
                public Authorization createFromParcel(Parcel in) {
                    return new Authorization();
                }
                public Authorization[] newArray(int size) {
                    return new Authorization[size];
                }
            };

    @Override
    public int describeContents() { return 0; }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }
}
