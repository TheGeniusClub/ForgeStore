/*
 * This file is part of ForgeStore
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program;
 * if not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2026 TheGeniusClub
 */

#include "binder/Binder.h"
#include "binder/BpBinder.h"
#include "binder/IInterface.h"
#include "binder/IPCThreadState.h"
#include "binder/IServiceManager.h"
#include "binder/RpcSession.h"
#include "binder/Status.h"

namespace android {

IInterface::IInterface() {}
IInterface::~IInterface() {}

IBinder::IBinder() {}
IBinder::~IBinder() {}
sp<IInterface> IBinder::queryLocalInterface(const String16 &) { return nullptr; }
BBinder *IBinder::localBinder() { return nullptr; }
BpBinder *IBinder::remoteBinder() { return nullptr; }
bool IBinder::checkSubclass(const void *) const { return false; }
void IBinder::withLock(const std::function<void()> &) {}
status_t IBinder::getExtension(sp<IBinder> *) { return INVALID_OPERATION; }
status_t IBinder::getDebugPid(pid_t *) { return INVALID_OPERATION; }
status_t IBinder::setRpcClientDebug(binder::unique_fd, const sp<IBinder> &) { return INVALID_OPERATION; }
status_t IBinder::addFrozenStateChangeCallback(const wp<FrozenStateChangeCallback> &) { return INVALID_OPERATION; }
status_t IBinder::removeFrozenStateChangeCallback(const wp<FrozenStateChangeCallback> &) { return INVALID_OPERATION; }
sp<IBinder> IBinder::lookupOrCreateWeak(const void *, object_make_func, const void *) { return nullptr; }

#ifdef __LP64__
static_assert(sizeof(IBinder) == 24);
static_assert(sizeof(BBinder) == 40);
#else
static_assert(sizeof(IBinder) == 12);
static_assert(sizeof(BBinder) == 20);
#endif

BBinder::BBinder() {}
BBinder::~BBinder() {}
const String16 &BBinder::getInterfaceDescriptor() const { __builtin_unreachable(); }
bool BBinder::isBinderAlive() const { return true; }
status_t BBinder::pingBinder() { return OK; }
status_t BBinder::dump(int, const Vector<String16> &) { return OK; }
status_t BBinder::transact(uint32_t, const Parcel &, Parcel *, uint32_t) { return OK; }
status_t BBinder::linkToDeath(const sp<DeathRecipient> &, void *, uint32_t) { return INVALID_OPERATION; }
status_t BBinder::unlinkToDeath(const wp<DeathRecipient> &, void *, uint32_t, wp<DeathRecipient> *) { return INVALID_OPERATION; }
void *BBinder::attachObject(const void *, void *, void *, object_cleanup_func) { return nullptr; }
void *BBinder::findObject(const void *) const { return nullptr; }
void *BBinder::detachObject(const void *) { return nullptr; }
void BBinder::withLock(const std::function<void()> &) {}
sp<IBinder> BBinder::lookupOrCreateWeak(const void *, IBinder::object_make_func, const void *) { return nullptr; }
BBinder *BBinder::localBinder() { return this; }
bool BBinder::isRequestingSid() { return false; }
void BBinder::setRequestingSid(bool) {}
sp<IBinder> BBinder::getExtension() { return nullptr; }
void BBinder::setExtension(const sp<IBinder> &) {}
void BBinder::setMinSchedulerPolicy(int, int) {}
int BBinder::getMinSchedulerPolicy() { return 0; }
int BBinder::getMinSchedulerPriority() { return 0; }
bool BBinder::isInheritRt() { return false; }
void BBinder::setInheritRt(bool) {}
pid_t BBinder::getDebugPid() { return 0; }
bool BBinder::wasParceled() { return false; }
void BBinder::setParceled() {}
status_t BBinder::setRpcClientDebug(binder::unique_fd, const sp<IBinder> &) { return INVALID_OPERATION; }
status_t BBinder::onTransact(uint32_t, const Parcel &, Parcel *, uint32_t) { return OK; }

BpRefBase::BpRefBase(const sp<IBinder> &o) : mRemote(o.get()), mRefs(nullptr), mState(0) {}
BpRefBase::~BpRefBase() {}
void BpRefBase::onFirstRef() {}
void BpRefBase::onLastStrongRef(const void *) {}
bool BpRefBase::onIncStrongAttempted(uint32_t, const void *) { return false; }

IPCThreadState *IPCThreadState::self() { return nullptr; }
IPCThreadState *IPCThreadState::selfOrNull() { return nullptr; }
pid_t IPCThreadState::getCallingPid() const { return 0; }
const char *IPCThreadState::getCallingSid() const { return nullptr; }
uid_t IPCThreadState::getCallingUid() const { return 0; }

#ifdef __LP64__
static_assert(sizeof(Parcel) == 120);
#else
static_assert(sizeof(Parcel) == 60);
#endif

Parcel::Parcel() {}
Parcel::~Parcel() {}
const uint8_t *Parcel::data() const { return nullptr; }
size_t Parcel::dataSize() const { return 0; }
size_t Parcel::dataAvail() const { return 0; }
size_t Parcel::dataPosition() const { return 0; }
size_t Parcel::dataCapacity() const { return 0; }
size_t Parcel::dataBufferSize() const { return 0; }
status_t Parcel::setDataSize(size_t) { return OK; }
void Parcel::setDataPosition(size_t) const {}
status_t Parcel::setDataCapacity(size_t) { return OK; }
status_t Parcel::setData(const uint8_t *, size_t) { return OK; }
status_t Parcel::appendFrom(const Parcel *, size_t, size_t) { return OK; }
int Parcel::compareData(const Parcel &) const { return 0; }
status_t Parcel::compareDataInRange(size_t, const Parcel &, size_t, size_t, int *) const { return OK; }
bool Parcel::allowFds() const { return true; }
bool Parcel::pushAllowFds(bool) { return true; }
void Parcel::restoreAllowFds(bool) {}
bool Parcel::hasFileDescriptors() const { return false; }
status_t Parcel::hasBinders(bool *) const { return OK; }
status_t Parcel::hasFileDescriptorsInRange(size_t, size_t, bool *) const { return OK; }
status_t Parcel::hasBindersInRange(size_t, size_t, bool *) const { return OK; }
std::vector<sp<IBinder>> Parcel::debugReadAllStrongBinders() const { return {}; }
std::vector<int> Parcel::debugReadAllFileDescriptors() const { return {}; }
void Parcel::markSensitive() const {}
void Parcel::markForBinder(const sp<IBinder> &) {}
void Parcel::markForRpc(const sp<RpcSession> &) {}
bool Parcel::isForRpc() const { return false; }
status_t Parcel::writeInterfaceToken(const String16 &) { return OK; }
status_t Parcel::writeInterfaceToken(const char16_t *, size_t) { return OK; }
bool Parcel::enforceInterface(const String16 &, IPCThreadState *) const { return true; }
bool Parcel::enforceInterface(const char16_t *, size_t, IPCThreadState *) const { return true; }
bool Parcel::checkInterface(IBinder *) const { return true; }
binder::Status Parcel::enforceNoDataAvail() const { return {}; }
void Parcel::setEnforceNoDataAvail(bool) {}
void Parcel::setServiceFuzzing() {}
bool Parcel::isServiceFuzzing() const { return false; }
void Parcel::freeData() {}
size_t Parcel::objectsCount() const { return 0; }
status_t Parcel::errorCheck() const { return OK; }
void Parcel::setError(status_t) {}
status_t Parcel::write(const void *, size_t) { return OK; }
void *Parcel::writeInplace(size_t) { return nullptr; }
status_t Parcel::writeInt32(int32_t) { return OK; }
status_t Parcel::writeUint32(uint32_t) { return OK; }
status_t Parcel::writeInt64(int64_t) { return OK; }
status_t Parcel::writeUint64(uint64_t) { return OK; }
status_t Parcel::writeFloat(float) { return OK; }
status_t Parcel::writeDouble(double) { return OK; }
status_t Parcel::writeCString(const char *) { return OK; }
status_t Parcel::writeString8(const String8 &) { return OK; }
status_t Parcel::writeString8(const char *, size_t) { return OK; }
status_t Parcel::writeString16(const String16 &) { return OK; }
status_t Parcel::writeString16(const std::optional<String16> &) { return OK; }
status_t Parcel::writeString16(const char16_t *, size_t) { return OK; }
status_t Parcel::writeStrongBinder(const sp<IBinder> &) { return OK; }
status_t Parcel::writeInt32Array(size_t, const int32_t *) { return OK; }
status_t Parcel::writeByteArray(size_t, const uint8_t *) { return OK; }
status_t Parcel::writeBool(bool) { return OK; }
status_t Parcel::writeChar(char16_t) { return OK; }
status_t Parcel::writeByte(int8_t) { return OK; }
status_t Parcel::writeUtf8AsUtf16(const std::string &) { return OK; }
status_t Parcel::writeUtf8AsUtf16(const std::optional<std::string> &) { return OK; }
status_t Parcel::writeByteVector(const std::optional<std::vector<int8_t>> &) { return OK; }
status_t Parcel::writeByteVector(const std::vector<int8_t> &) { return OK; }
status_t Parcel::writeByteVector(const std::optional<std::vector<uint8_t>> &) { return OK; }
status_t Parcel::writeByteVector(const std::vector<uint8_t> &) { return OK; }
status_t Parcel::writeInt32Vector(const std::optional<std::vector<int32_t>> &) { return OK; }
status_t Parcel::writeInt32Vector(const std::vector<int32_t> &) { return OK; }
status_t Parcel::writeInt64Vector(const std::optional<std::vector<int64_t>> &) { return OK; }
status_t Parcel::writeInt64Vector(const std::vector<int64_t> &) { return OK; }
status_t Parcel::writeUint64Vector(const std::optional<std::vector<uint64_t>> &) { return OK; }
status_t Parcel::writeUint64Vector(const std::vector<uint64_t> &) { return OK; }
status_t Parcel::writeFloatVector(const std::optional<std::vector<float>> &) { return OK; }
status_t Parcel::writeFloatVector(const std::vector<float> &) { return OK; }
status_t Parcel::writeDoubleVector(const std::optional<std::vector<double>> &) { return OK; }
status_t Parcel::writeDoubleVector(const std::vector<double> &) { return OK; }
status_t Parcel::writeBoolVector(const std::optional<std::vector<bool>> &) { return OK; }
status_t Parcel::writeBoolVector(const std::vector<bool> &) { return OK; }
status_t Parcel::writeCharVector(const std::optional<std::vector<char16_t>> &) { return OK; }
status_t Parcel::writeCharVector(const std::vector<char16_t> &) { return OK; }
status_t Parcel::writeString16Vector(const std::optional<std::vector<std::optional<String16>>> &) { return OK; }
status_t Parcel::writeString16Vector(const std::vector<String16> &) { return OK; }
status_t Parcel::writeUtf8VectorAsUtf16Vector(const std::optional<std::vector<std::optional<std::string>>> &) { return OK; }
status_t Parcel::writeUtf8VectorAsUtf16Vector(const std::vector<std::string> &) { return OK; }
status_t Parcel::writeStrongBinderVector(const std::optional<std::vector<sp<IBinder>>> &) { return OK; }
status_t Parcel::writeStrongBinderVector(const std::vector<sp<IBinder>> &) { return OK; }
status_t Parcel::writeParcelable(const Parcelable &) { return OK; }
status_t Parcel::writeNativeHandle(const native_handle *) { return OK; }
status_t Parcel::writeFileDescriptor(int, bool) { return OK; }
status_t Parcel::writeDupFileDescriptor(int) { return OK; }
status_t Parcel::writeParcelFileDescriptor(int, bool) { return OK; }
status_t Parcel::writeDupParcelFileDescriptor(int) { return OK; }
status_t Parcel::writeUniqueFileDescriptor(const binder::unique_fd &) { return OK; }
status_t Parcel::writeUniqueFileDescriptorVector(const std::optional<std::vector<binder::unique_fd>> &) { return OK; }
status_t Parcel::writeUniqueFileDescriptorVector(const std::vector<binder::unique_fd> &) { return OK; }
status_t Parcel::writeBlob(size_t, bool, WritableBlob *) { return OK; }
status_t Parcel::writeDupImmutableBlobFileDescriptor(int) { return OK; }
status_t Parcel::writeNoException() { return OK; }
status_t Parcel::read(void *, size_t) const { return OK; }
const void *Parcel::readInplace(size_t) const { return nullptr; }
int32_t Parcel::readInt32() const { return 0; }
status_t Parcel::readInt32(int32_t *) const { return OK; }
uint32_t Parcel::readUint32() const { return 0; }
status_t Parcel::readUint32(uint32_t *) const { return OK; }
int64_t Parcel::readInt64() const { return 0; }
status_t Parcel::readInt64(int64_t *) const { return OK; }
uint64_t Parcel::readUint64() const { return 0; }
status_t Parcel::readUint64(uint64_t *) const { return OK; }
float Parcel::readFloat() const { return 0; }
status_t Parcel::readFloat(float *) const { return OK; }
double Parcel::readDouble() const { return 0; }
status_t Parcel::readDouble(double *) const { return OK; }
bool Parcel::readBool() const { return false; }
status_t Parcel::readBool(bool *) const { return OK; }
char16_t Parcel::readChar() const { return 0; }
status_t Parcel::readChar(char16_t *) const { return OK; }
int8_t Parcel::readByte() const { return 0; }
status_t Parcel::readByte(int8_t *) const { return OK; }
status_t Parcel::readUtf8FromUtf16(std::string *) const { return OK; }
status_t Parcel::readUtf8FromUtf16(std::optional<std::string> *) const { return OK; }
const char *Parcel::readCString() const { return nullptr; }
String8 Parcel::readString8() const { return String8(); }
status_t Parcel::readString8(String8 *) const { return OK; }
const char *Parcel::readString8Inplace(size_t *) const { return nullptr; }
String16 Parcel::readString16() const { return String16(); }
status_t Parcel::readString16(String16 *) const { return OK; }
status_t Parcel::readString16(std::optional<String16> *) const { return OK; }
const char16_t *Parcel::readString16Inplace(size_t *) const { return nullptr; }
sp<IBinder> Parcel::readStrongBinder() const { return nullptr; }
status_t Parcel::readStrongBinder(sp<IBinder> *) const { return OK; }
status_t Parcel::readNullableStrongBinder(sp<IBinder> *) const { return OK; }
status_t Parcel::readParcelable(Parcelable *) const { return OK; }
status_t Parcel::readStrongBinderVector(std::optional<std::vector<sp<IBinder>>> *) const { return OK; }
status_t Parcel::readStrongBinderVector(std::vector<sp<IBinder>> *) const { return OK; }
status_t Parcel::readByteVector(std::optional<std::vector<int8_t>> *) const { return OK; }
status_t Parcel::readByteVector(std::vector<int8_t> *) const { return OK; }
status_t Parcel::readByteVector(std::optional<std::vector<uint8_t>> *) const { return OK; }
status_t Parcel::readByteVector(std::vector<uint8_t> *) const { return OK; }
status_t Parcel::readInt32Vector(std::optional<std::vector<int32_t>> *) const { return OK; }
status_t Parcel::readInt32Vector(std::vector<int32_t> *) const { return OK; }
status_t Parcel::readInt64Vector(std::optional<std::vector<int64_t>> *) const { return OK; }
status_t Parcel::readInt64Vector(std::vector<int64_t> *) const { return OK; }
status_t Parcel::readUint64Vector(std::optional<std::vector<uint64_t>> *) const { return OK; }
status_t Parcel::readUint64Vector(std::vector<uint64_t> *) const { return OK; }
status_t Parcel::readFloatVector(std::optional<std::vector<float>> *) const { return OK; }
status_t Parcel::readFloatVector(std::vector<float> *) const { return OK; }
status_t Parcel::readDoubleVector(std::optional<std::vector<double>> *) const { return OK; }
status_t Parcel::readDoubleVector(std::vector<double> *) const { return OK; }
status_t Parcel::readBoolVector(std::optional<std::vector<bool>> *) const { return OK; }
status_t Parcel::readBoolVector(std::vector<bool> *) const { return OK; }
status_t Parcel::readCharVector(std::optional<std::vector<char16_t>> *) const { return OK; }
status_t Parcel::readCharVector(std::vector<char16_t> *) const { return OK; }
status_t Parcel::readString16Vector(std::optional<std::vector<std::optional<String16>>> *) const { return OK; }
status_t Parcel::readString16Vector(std::vector<String16> *) const { return OK; }
status_t Parcel::readUtf8VectorFromUtf16Vector(std::optional<std::vector<std::optional<std::string>>> *) const { return OK; }
status_t Parcel::readUtf8VectorFromUtf16Vector(std::vector<std::string> *) const { return OK; }
int32_t Parcel::readExceptionCode() const { return 0; }
native_handle *Parcel::readNativeHandle() const { return nullptr; }
int Parcel::readFileDescriptor() const { return -1; }
int Parcel::readParcelFileDescriptor() const { return -1; }
status_t Parcel::readUniqueFileDescriptor(binder::unique_fd *) const { return OK; }
status_t Parcel::readUniqueParcelFileDescriptor(binder::unique_fd *) const { return OK; }
status_t Parcel::readUniqueFileDescriptorVector(std::optional<std::vector<binder::unique_fd>> *) const { return OK; }
status_t Parcel::readUniqueFileDescriptorVector(std::vector<binder::unique_fd> *) const { return OK; }
status_t Parcel::readBlob(size_t, ReadableBlob *) const { return OK; }
const flat_binder_object *Parcel::readObject(bool) const { return nullptr; }
size_t Parcel::getGlobalAllocSize() { return 0; }
size_t Parcel::getGlobalAllocCount() { return 0; }
bool Parcel::replaceCallingWorkSourceUid(uid_t) { return false; }
uid_t Parcel::readCallingWorkSourceUid() const { return 0; }
void Parcel::print(std::ostream &, uint32_t) const {}

IServiceManager::IServiceManager() {}
IServiceManager::~IServiceManager() {}
const String16 &IServiceManager::getInterfaceDescriptor() const { __builtin_unreachable(); }
sp<IServiceManager> defaultServiceManager() { return nullptr; }
void setDefaultServiceManager(const sp<IServiceManager> &) {}

} // namespace android
