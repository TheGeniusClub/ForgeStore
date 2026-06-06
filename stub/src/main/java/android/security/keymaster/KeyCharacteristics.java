package android.security.keymaster;

import android.os.Parcel;
import android.os.Parcelable;

public class KeyCharacteristics implements Parcelable {
    public KeymasterArguments swEnforced = new KeymasterArguments();
    public KeymasterArguments hwEnforced = new KeymasterArguments();

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }

    @Override
    public int describeContents() {
        throw new UnsupportedOperationException("STUB!");
    }

    public static final Creator<KeyCharacteristics> CREATOR = new Creator<KeyCharacteristics>() {
        @Override
        public KeyCharacteristics createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }
        @Override
        public KeyCharacteristics[] newArray(int size) {
            return new KeyCharacteristics[size];
        }
    };
}
