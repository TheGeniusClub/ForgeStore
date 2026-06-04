package android.system.keystore2;

import android.os.Parcel;
import android.os.Parcelable;

public class OperationChallenge implements Parcelable {
    public long challenge = 0L;

    public static final Creator<OperationChallenge> CREATOR = new Creator<>() {
        public OperationChallenge createFromParcel(Parcel in) {
            OperationChallenge c = new OperationChallenge();
            c.challenge = in.readLong();
            return c;
        }
        public OperationChallenge[] newArray(int size) {
            return new OperationChallenge[size];
        }
    };

    @Override
    public int describeContents() { return 0; }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeLong(challenge);
    }
}
