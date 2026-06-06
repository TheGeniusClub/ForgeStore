package android.security.keymaster;

import android.os.Parcel;
import android.os.Parcelable;

public class KeymasterArguments implements Parcelable {
    public void addEnum(int tag, int value) {
        throw new UnsupportedOperationException("STUB!");
    }

    public int getEnum(int tag, int defaultValue) {
        throw new UnsupportedOperationException("STUB!");
    }

    public java.util.List<Integer> getEnums(int tag) {
        throw new UnsupportedOperationException("STUB!");
    }

    public byte[] getBytes(int tag, byte[] defaultValue) {
        throw new UnsupportedOperationException("STUB!");
    }

    public long getUnsignedInt(int tag, long defaultValue) {
        throw new UnsupportedOperationException("STUB!");
    }

    public java.util.Date getDate(int tag, java.util.Date defaultValue) {
        throw new UnsupportedOperationException("STUB!");
    }

    public void readFromParcel(Parcel in) {
        throw new UnsupportedOperationException("STUB!");
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }

    @Override
    public int describeContents() {
        throw new UnsupportedOperationException("STUB!");
    }

    public static final Creator<KeymasterArguments> CREATOR = new Creator<KeymasterArguments>() {
        @Override
        public KeymasterArguments createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }
        @Override
        public KeymasterArguments[] newArray(int size) {
            return new KeymasterArguments[size];
        }
    };
}
