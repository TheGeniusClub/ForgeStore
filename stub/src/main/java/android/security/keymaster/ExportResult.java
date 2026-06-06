package android.security.keymaster;

import android.os.Parcel;
import android.os.Parcelable;

public class ExportResult implements Parcelable {
    public int resultCode;
    public byte[] exportData;

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }

    @Override
    public int describeContents() {
        throw new UnsupportedOperationException("STUB!");
    }

    public static final Creator<ExportResult> CREATOR = new Creator<ExportResult>() {
        @Override
        public ExportResult createFromParcel(Parcel in) {
            throw new UnsupportedOperationException("STUB!");
        }
        @Override
        public ExportResult[] newArray(int size) {
            return new ExportResult[size];
        }
    };
}
