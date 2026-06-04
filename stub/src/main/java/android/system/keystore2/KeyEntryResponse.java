package android.system.keystore2;

import android.os.Parcel;
import android.os.Parcelable;

public class KeyEntryResponse implements Parcelable {
    public KeyMetadata metadata;
    public IKeystoreSecurityLevel iSecurityLevel;

    public static final Parcelable.Creator<KeyEntryResponse> CREATOR =
            new Parcelable.Creator<>() {
                public KeyEntryResponse createFromParcel(Parcel in) {
                    return new KeyEntryResponse();
                }
                public KeyEntryResponse[] newArray(int size) {
                    return new KeyEntryResponse[size];
                }
            };

    @Override
    public int describeContents() { return 0; }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }
}
