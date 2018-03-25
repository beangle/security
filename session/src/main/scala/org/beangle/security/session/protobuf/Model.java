/*
 * Beangle, Agile Development Scaffold and Toolkits.
 *
 * Copyright © 2005, The Beangle Software.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.beangle.security.session.protobuf;

public final class Model {
  private Model() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  public interface AccountOrBuilder extends
      // @@protoc_insertion_point(interface_extends:Account)
      com.google.protobuf.MessageOrBuilder {

    /**
     * <code>string name = 1;</code>
     */
    java.lang.String getName();
    /**
     * <code>string name = 1;</code>
     */
    com.google.protobuf.ByteString
        getNameBytes();

    /**
     * <code>string description = 2;</code>
     */
    java.lang.String getDescription();
    /**
     * <code>string description = 2;</code>
     */
    com.google.protobuf.ByteString
        getDescriptionBytes();

    /**
     * <code>string remoteToken = 3;</code>
     */
    java.lang.String getRemoteToken();
    /**
     * <code>string remoteToken = 3;</code>
     */
    com.google.protobuf.ByteString
        getRemoteTokenBytes();

    /**
     * <code>int32 status = 4;</code>
     */
    int getStatus();

    /**
     * <code>string authorities = 5;</code>
     */
    java.lang.String getAuthorities();
    /**
     * <code>string authorities = 5;</code>
     */
    com.google.protobuf.ByteString
        getAuthoritiesBytes();

    /**
     * <code>string permissions = 6;</code>
     */
    java.lang.String getPermissions();
    /**
     * <code>string permissions = 6;</code>
     */
    com.google.protobuf.ByteString
        getPermissionsBytes();

    /**
     * <code>map&lt;string, string&gt; details = 7;</code>
     */
    int getDetailsCount();
    /**
     * <code>map&lt;string, string&gt; details = 7;</code>
     */
    boolean containsDetails(
        java.lang.String key);
    /**
     * Use {@link #getDetailsMap()} instead.
     */
    @java.lang.Deprecated
    java.util.Map<java.lang.String, java.lang.String>
    getDetails();
    /**
     * <code>map&lt;string, string&gt; details = 7;</code>
     */
    java.util.Map<java.lang.String, java.lang.String>
    getDetailsMap();
    /**
     * <code>map&lt;string, string&gt; details = 7;</code>
     */

    java.lang.String getDetailsOrDefault(
        java.lang.String key,
        java.lang.String defaultValue);
    /**
     * <code>map&lt;string, string&gt; details = 7;</code>
     */

    java.lang.String getDetailsOrThrow(
        java.lang.String key);
  }
  /**
   * Protobuf type {@code Account}
   */
  public  static final class Account extends
      com.google.protobuf.GeneratedMessageV3 implements
      // @@protoc_insertion_point(message_implements:Account)
      AccountOrBuilder {
  private static final long serialVersionUID = 0L;
    // Use Account.newBuilder() to construct.
    private Account(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
      super(builder);
    }
    private Account() {
      name_ = "";
      description_ = "";
      remoteToken_ = "";
      status_ = 0;
      authorities_ = "";
      permissions_ = "";
    }

    @java.lang.Override
    public final com.google.protobuf.UnknownFieldSet
    getUnknownFields() {
      return this.unknownFields;
    }
    private Account(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      this();
      if (extensionRegistry == null) {
        throw new java.lang.NullPointerException();
      }
      int mutable_bitField0_ = 0;
      com.google.protobuf.UnknownFieldSet.Builder unknownFields =
          com.google.protobuf.UnknownFieldSet.newBuilder();
      try {
        boolean done = false;
        while (!done) {
          int tag = input.readTag();
          switch (tag) {
            case 0:
              done = true;
              break;
            default: {
              if (!parseUnknownFieldProto3(
                  input, unknownFields, extensionRegistry, tag)) {
                done = true;
              }
              break;
            }
            case 10: {
              java.lang.String s = input.readStringRequireUtf8();

              name_ = s;
              break;
            }
            case 18: {
              java.lang.String s = input.readStringRequireUtf8();

              description_ = s;
              break;
            }
            case 26: {
              java.lang.String s = input.readStringRequireUtf8();

              remoteToken_ = s;
              break;
            }
            case 32: {

              status_ = input.readInt32();
              break;
            }
            case 42: {
              java.lang.String s = input.readStringRequireUtf8();

              authorities_ = s;
              break;
            }
            case 50: {
              java.lang.String s = input.readStringRequireUtf8();

              permissions_ = s;
              break;
            }
            case 58: {
              if (!((mutable_bitField0_ & 0x00000040) == 0x00000040)) {
                details_ = com.google.protobuf.MapField.newMapField(
                    DetailsDefaultEntryHolder.defaultEntry);
                mutable_bitField0_ |= 0x00000040;
              }
              com.google.protobuf.MapEntry<java.lang.String, java.lang.String>
              details__ = input.readMessage(
                  DetailsDefaultEntryHolder.defaultEntry.getParserForType(), extensionRegistry);
              details_.getMutableMap().put(
                  details__.getKey(), details__.getValue());
              break;
            }
          }
        }
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        throw e.setUnfinishedMessage(this);
      } catch (java.io.IOException e) {
        throw new com.google.protobuf.InvalidProtocolBufferException(
            e).setUnfinishedMessage(this);
      } finally {
        this.unknownFields = unknownFields.build();
        makeExtensionsImmutable();
      }
    }
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return org.beangle.security.session.protobuf.Model.internal_static_Account_descriptor;
    }

    @SuppressWarnings({"rawtypes"})
    protected com.google.protobuf.MapField internalGetMapField(
        int number) {
      switch (number) {
        case 7:
          return internalGetDetails();
        default:
          throw new RuntimeException(
              "Invalid map field number: " + number);
      }
    }
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return org.beangle.security.session.protobuf.Model.internal_static_Account_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              org.beangle.security.session.protobuf.Model.Account.class, org.beangle.security.session.protobuf.Model.Account.Builder.class);
    }

    private int bitField0_;
    public static final int NAME_FIELD_NUMBER = 1;
    private volatile java.lang.Object name_;
    /**
     * <code>string name = 1;</code>
     */
    public java.lang.String getName() {
      java.lang.Object ref = name_;
      if (ref instanceof java.lang.String) {
        return (java.lang.String) ref;
      } else {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        name_ = s;
        return s;
      }
    }
    /**
     * <code>string name = 1;</code>
     */
    public com.google.protobuf.ByteString
        getNameBytes() {
      java.lang.Object ref = name_;
      if (ref instanceof java.lang.String) {
        com.google.protobuf.ByteString b =
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        name_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }

    public static final int DESCRIPTION_FIELD_NUMBER = 2;
    private volatile java.lang.Object description_;
    /**
     * <code>string description = 2;</code>
     */
    public java.lang.String getDescription() {
      java.lang.Object ref = description_;
      if (ref instanceof java.lang.String) {
        return (java.lang.String) ref;
      } else {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        description_ = s;
        return s;
      }
    }
    /**
     * <code>string description = 2;</code>
     */
    public com.google.protobuf.ByteString
        getDescriptionBytes() {
      java.lang.Object ref = description_;
      if (ref instanceof java.lang.String) {
        com.google.protobuf.ByteString b =
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        description_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }

    public static final int REMOTETOKEN_FIELD_NUMBER = 3;
    private volatile java.lang.Object remoteToken_;
    /**
     * <code>string remoteToken = 3;</code>
     */
    public java.lang.String getRemoteToken() {
      java.lang.Object ref = remoteToken_;
      if (ref instanceof java.lang.String) {
        return (java.lang.String) ref;
      } else {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        remoteToken_ = s;
        return s;
      }
    }
    /**
     * <code>string remoteToken = 3;</code>
     */
    public com.google.protobuf.ByteString
        getRemoteTokenBytes() {
      java.lang.Object ref = remoteToken_;
      if (ref instanceof java.lang.String) {
        com.google.protobuf.ByteString b =
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        remoteToken_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }

    public static final int STATUS_FIELD_NUMBER = 4;
    private int status_;
    /**
     * <code>int32 status = 4;</code>
     */
    public int getStatus() {
      return status_;
    }

    public static final int AUTHORITIES_FIELD_NUMBER = 5;
    private volatile java.lang.Object authorities_;
    /**
     * <code>string authorities = 5;</code>
     */
    public java.lang.String getAuthorities() {
      java.lang.Object ref = authorities_;
      if (ref instanceof java.lang.String) {
        return (java.lang.String) ref;
      } else {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        authorities_ = s;
        return s;
      }
    }
    /**
     * <code>string authorities = 5;</code>
     */
    public com.google.protobuf.ByteString
        getAuthoritiesBytes() {
      java.lang.Object ref = authorities_;
      if (ref instanceof java.lang.String) {
        com.google.protobuf.ByteString b =
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        authorities_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }

    public static final int PERMISSIONS_FIELD_NUMBER = 6;
    private volatile java.lang.Object permissions_;
    /**
     * <code>string permissions = 6;</code>
     */
    public java.lang.String getPermissions() {
      java.lang.Object ref = permissions_;
      if (ref instanceof java.lang.String) {
        return (java.lang.String) ref;
      } else {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        permissions_ = s;
        return s;
      }
    }
    /**
     * <code>string permissions = 6;</code>
     */
    public com.google.protobuf.ByteString
        getPermissionsBytes() {
      java.lang.Object ref = permissions_;
      if (ref instanceof java.lang.String) {
        com.google.protobuf.ByteString b =
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        permissions_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }

    public static final int DETAILS_FIELD_NUMBER = 7;
    private static final class DetailsDefaultEntryHolder {
      static final com.google.protobuf.MapEntry<
          java.lang.String, java.lang.String> defaultEntry =
              com.google.protobuf.MapEntry
              .<java.lang.String, java.lang.String>newDefaultInstance(
                  org.beangle.security.session.protobuf.Model.internal_static_Account_DetailsEntry_descriptor,
                  com.google.protobuf.WireFormat.FieldType.STRING,
                  "",
                  com.google.protobuf.WireFormat.FieldType.STRING,
                  "");
    }
    private com.google.protobuf.MapField<
        java.lang.String, java.lang.String> details_;
    private com.google.protobuf.MapField<java.lang.String, java.lang.String>
    internalGetDetails() {
      if (details_ == null) {
        return com.google.protobuf.MapField.emptyMapField(
            DetailsDefaultEntryHolder.defaultEntry);
      }
      return details_;
    }

    public int getDetailsCount() {
      return internalGetDetails().getMap().size();
    }
    /**
     * <code>map&lt;string, string&gt; details = 7;</code>
     */

    public boolean containsDetails(
        java.lang.String key) {
      if (key == null) { throw new java.lang.NullPointerException(); }
      return internalGetDetails().getMap().containsKey(key);
    }
    /**
     * Use {@link #getDetailsMap()} instead.
     */
    @java.lang.Deprecated
    public java.util.Map<java.lang.String, java.lang.String> getDetails() {
      return getDetailsMap();
    }
    /**
     * <code>map&lt;string, string&gt; details = 7;</code>
     */

    public java.util.Map<java.lang.String, java.lang.String> getDetailsMap() {
      return internalGetDetails().getMap();
    }
    /**
     * <code>map&lt;string, string&gt; details = 7;</code>
     */

    public java.lang.String getDetailsOrDefault(
        java.lang.String key,
        java.lang.String defaultValue) {
      if (key == null) { throw new java.lang.NullPointerException(); }
      java.util.Map<java.lang.String, java.lang.String> map =
          internalGetDetails().getMap();
      return map.containsKey(key) ? map.get(key) : defaultValue;
    }
    /**
     * <code>map&lt;string, string&gt; details = 7;</code>
     */

    public java.lang.String getDetailsOrThrow(
        java.lang.String key) {
      if (key == null) { throw new java.lang.NullPointerException(); }
      java.util.Map<java.lang.String, java.lang.String> map =
          internalGetDetails().getMap();
      if (!map.containsKey(key)) {
        throw new java.lang.IllegalArgumentException();
      }
      return map.get(key);
    }

    private byte memoizedIsInitialized = -1;
    public final boolean isInitialized() {
      byte isInitialized = memoizedIsInitialized;
      if (isInitialized == 1) return true;
      if (isInitialized == 0) return false;

      memoizedIsInitialized = 1;
      return true;
    }

    public void writeTo(com.google.protobuf.CodedOutputStream output)
                        throws java.io.IOException {
      if (!getNameBytes().isEmpty()) {
        com.google.protobuf.GeneratedMessageV3.writeString(output, 1, name_);
      }
      if (!getDescriptionBytes().isEmpty()) {
        com.google.protobuf.GeneratedMessageV3.writeString(output, 2, description_);
      }
      if (!getRemoteTokenBytes().isEmpty()) {
        com.google.protobuf.GeneratedMessageV3.writeString(output, 3, remoteToken_);
      }
      if (status_ != 0) {
        output.writeInt32(4, status_);
      }
      if (!getAuthoritiesBytes().isEmpty()) {
        com.google.protobuf.GeneratedMessageV3.writeString(output, 5, authorities_);
      }
      if (!getPermissionsBytes().isEmpty()) {
        com.google.protobuf.GeneratedMessageV3.writeString(output, 6, permissions_);
      }
      com.google.protobuf.GeneratedMessageV3
        .serializeStringMapTo(
          output,
          internalGetDetails(),
          DetailsDefaultEntryHolder.defaultEntry,
          7);
      unknownFields.writeTo(output);
    }

    public int getSerializedSize() {
      int size = memoizedSize;
      if (size != -1) return size;

      size = 0;
      if (!getNameBytes().isEmpty()) {
        size += com.google.protobuf.GeneratedMessageV3.computeStringSize(1, name_);
      }
      if (!getDescriptionBytes().isEmpty()) {
        size += com.google.protobuf.GeneratedMessageV3.computeStringSize(2, description_);
      }
      if (!getRemoteTokenBytes().isEmpty()) {
        size += com.google.protobuf.GeneratedMessageV3.computeStringSize(3, remoteToken_);
      }
      if (status_ != 0) {
        size += com.google.protobuf.CodedOutputStream
          .computeInt32Size(4, status_);
      }
      if (!getAuthoritiesBytes().isEmpty()) {
        size += com.google.protobuf.GeneratedMessageV3.computeStringSize(5, authorities_);
      }
      if (!getPermissionsBytes().isEmpty()) {
        size += com.google.protobuf.GeneratedMessageV3.computeStringSize(6, permissions_);
      }
      for (java.util.Map.Entry<java.lang.String, java.lang.String> entry
           : internalGetDetails().getMap().entrySet()) {
        com.google.protobuf.MapEntry<java.lang.String, java.lang.String>
        details__ = DetailsDefaultEntryHolder.defaultEntry.newBuilderForType()
            .setKey(entry.getKey())
            .setValue(entry.getValue())
            .build();
        size += com.google.protobuf.CodedOutputStream
            .computeMessageSize(7, details__);
      }
      size += unknownFields.getSerializedSize();
      memoizedSize = size;
      return size;
    }

    @java.lang.Override
    public boolean equals(final java.lang.Object obj) {
      if (obj == this) {
       return true;
      }
      if (!(obj instanceof org.beangle.security.session.protobuf.Model.Account)) {
        return super.equals(obj);
      }
      org.beangle.security.session.protobuf.Model.Account other = (org.beangle.security.session.protobuf.Model.Account) obj;

      boolean result = true;
      result = result && getName()
          .equals(other.getName());
      result = result && getDescription()
          .equals(other.getDescription());
      result = result && getRemoteToken()
          .equals(other.getRemoteToken());
      result = result && (getStatus()
          == other.getStatus());
      result = result && getAuthorities()
          .equals(other.getAuthorities());
      result = result && getPermissions()
          .equals(other.getPermissions());
      result = result && internalGetDetails().equals(
          other.internalGetDetails());
      result = result && unknownFields.equals(other.unknownFields);
      return result;
    }

    @java.lang.Override
    public int hashCode() {
      if (memoizedHashCode != 0) {
        return memoizedHashCode;
      }
      int hash = 41;
      hash = (19 * hash) + getDescriptor().hashCode();
      hash = (37 * hash) + NAME_FIELD_NUMBER;
      hash = (53 * hash) + getName().hashCode();
      hash = (37 * hash) + DESCRIPTION_FIELD_NUMBER;
      hash = (53 * hash) + getDescription().hashCode();
      hash = (37 * hash) + REMOTETOKEN_FIELD_NUMBER;
      hash = (53 * hash) + getRemoteToken().hashCode();
      hash = (37 * hash) + STATUS_FIELD_NUMBER;
      hash = (53 * hash) + getStatus();
      hash = (37 * hash) + AUTHORITIES_FIELD_NUMBER;
      hash = (53 * hash) + getAuthorities().hashCode();
      hash = (37 * hash) + PERMISSIONS_FIELD_NUMBER;
      hash = (53 * hash) + getPermissions().hashCode();
      if (!internalGetDetails().getMap().isEmpty()) {
        hash = (37 * hash) + DETAILS_FIELD_NUMBER;
        hash = (53 * hash) + internalGetDetails().hashCode();
      }
      hash = (29 * hash) + unknownFields.hashCode();
      memoizedHashCode = hash;
      return hash;
    }

    public static org.beangle.security.session.protobuf.Model.Account parseFrom(
        java.nio.ByteBuffer data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static org.beangle.security.session.protobuf.Model.Account parseFrom(
        java.nio.ByteBuffer data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static org.beangle.security.session.protobuf.Model.Account parseFrom(
        com.google.protobuf.ByteString data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static org.beangle.security.session.protobuf.Model.Account parseFrom(
        com.google.protobuf.ByteString data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static org.beangle.security.session.protobuf.Model.Account parseFrom(byte[] data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static org.beangle.security.session.protobuf.Model.Account parseFrom(
        byte[] data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static org.beangle.security.session.protobuf.Model.Account parseFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static org.beangle.security.session.protobuf.Model.Account parseFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }
    public static org.beangle.security.session.protobuf.Model.Account parseDelimitedFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input);
    }
    public static org.beangle.security.session.protobuf.Model.Account parseDelimitedFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
    }
    public static org.beangle.security.session.protobuf.Model.Account parseFrom(
        com.google.protobuf.CodedInputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static org.beangle.security.session.protobuf.Model.Account parseFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }

    public Builder newBuilderForType() { return newBuilder(); }
    public static Builder newBuilder() {
      return DEFAULT_INSTANCE.toBuilder();
    }
    public static Builder newBuilder(org.beangle.security.session.protobuf.Model.Account prototype) {
      return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
    }
    public Builder toBuilder() {
      return this == DEFAULT_INSTANCE
          ? new Builder() : new Builder().mergeFrom(this);
    }

    @java.lang.Override
    protected Builder newBuilderForType(
        com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
      Builder builder = new Builder(parent);
      return builder;
    }
    /**
     * Protobuf type {@code Account}
     */
    public static final class Builder extends
        com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
        // @@protoc_insertion_point(builder_implements:Account)
        org.beangle.security.session.protobuf.Model.AccountOrBuilder {
      public static final com.google.protobuf.Descriptors.Descriptor
          getDescriptor() {
        return org.beangle.security.session.protobuf.Model.internal_static_Account_descriptor;
      }

      @SuppressWarnings({"rawtypes"})
      protected com.google.protobuf.MapField internalGetMapField(
          int number) {
        switch (number) {
          case 7:
            return internalGetDetails();
          default:
            throw new RuntimeException(
                "Invalid map field number: " + number);
        }
      }
      @SuppressWarnings({"rawtypes"})
      protected com.google.protobuf.MapField internalGetMutableMapField(
          int number) {
        switch (number) {
          case 7:
            return internalGetMutableDetails();
          default:
            throw new RuntimeException(
                "Invalid map field number: " + number);
        }
      }
      protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
          internalGetFieldAccessorTable() {
        return org.beangle.security.session.protobuf.Model.internal_static_Account_fieldAccessorTable
            .ensureFieldAccessorsInitialized(
                org.beangle.security.session.protobuf.Model.Account.class, org.beangle.security.session.protobuf.Model.Account.Builder.class);
      }

      // Construct using org.beangle.security.session.protobuf.Model.Account.newBuilder()
      private Builder() {
        maybeForceBuilderInitialization();
      }

      private Builder(
          com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
        super(parent);
        maybeForceBuilderInitialization();
      }
      private void maybeForceBuilderInitialization() {
        if (com.google.protobuf.GeneratedMessageV3
                .alwaysUseFieldBuilders) {
        }
      }
      public Builder clear() {
        super.clear();
        name_ = "";

        description_ = "";

        remoteToken_ = "";

        status_ = 0;

        authorities_ = "";

        permissions_ = "";

        internalGetMutableDetails().clear();
        return this;
      }

      public com.google.protobuf.Descriptors.Descriptor
          getDescriptorForType() {
        return org.beangle.security.session.protobuf.Model.internal_static_Account_descriptor;
      }

      public org.beangle.security.session.protobuf.Model.Account getDefaultInstanceForType() {
        return org.beangle.security.session.protobuf.Model.Account.getDefaultInstance();
      }

      public org.beangle.security.session.protobuf.Model.Account build() {
        org.beangle.security.session.protobuf.Model.Account result = buildPartial();
        if (!result.isInitialized()) {
          throw newUninitializedMessageException(result);
        }
        return result;
      }

      public org.beangle.security.session.protobuf.Model.Account buildPartial() {
        org.beangle.security.session.protobuf.Model.Account result = new org.beangle.security.session.protobuf.Model.Account(this);
        int from_bitField0_ = bitField0_;
        int to_bitField0_ = 0;
        result.name_ = name_;
        result.description_ = description_;
        result.remoteToken_ = remoteToken_;
        result.status_ = status_;
        result.authorities_ = authorities_;
        result.permissions_ = permissions_;
        result.details_ = internalGetDetails();
        result.details_.makeImmutable();
        result.bitField0_ = to_bitField0_;
        onBuilt();
        return result;
      }

      public Builder clone() {
        return (Builder) super.clone();
      }
      public Builder setField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          java.lang.Object value) {
        return (Builder) super.setField(field, value);
      }
      public Builder clearField(
          com.google.protobuf.Descriptors.FieldDescriptor field) {
        return (Builder) super.clearField(field);
      }
      public Builder clearOneof(
          com.google.protobuf.Descriptors.OneofDescriptor oneof) {
        return (Builder) super.clearOneof(oneof);
      }
      public Builder setRepeatedField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          int index, java.lang.Object value) {
        return (Builder) super.setRepeatedField(field, index, value);
      }
      public Builder addRepeatedField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          java.lang.Object value) {
        return (Builder) super.addRepeatedField(field, value);
      }
      public Builder mergeFrom(com.google.protobuf.Message other) {
        if (other instanceof org.beangle.security.session.protobuf.Model.Account) {
          return mergeFrom((org.beangle.security.session.protobuf.Model.Account)other);
        } else {
          super.mergeFrom(other);
          return this;
        }
      }

      public Builder mergeFrom(org.beangle.security.session.protobuf.Model.Account other) {
        if (other == org.beangle.security.session.protobuf.Model.Account.getDefaultInstance()) return this;
        if (!other.getName().isEmpty()) {
          name_ = other.name_;
          onChanged();
        }
        if (!other.getDescription().isEmpty()) {
          description_ = other.description_;
          onChanged();
        }
        if (!other.getRemoteToken().isEmpty()) {
          remoteToken_ = other.remoteToken_;
          onChanged();
        }
        if (other.getStatus() != 0) {
          setStatus(other.getStatus());
        }
        if (!other.getAuthorities().isEmpty()) {
          authorities_ = other.authorities_;
          onChanged();
        }
        if (!other.getPermissions().isEmpty()) {
          permissions_ = other.permissions_;
          onChanged();
        }
        internalGetMutableDetails().mergeFrom(
            other.internalGetDetails());
        this.mergeUnknownFields(other.unknownFields);
        onChanged();
        return this;
      }

      public final boolean isInitialized() {
        return true;
      }

      public Builder mergeFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws java.io.IOException {
        org.beangle.security.session.protobuf.Model.Account parsedMessage = null;
        try {
          parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
        } catch (com.google.protobuf.InvalidProtocolBufferException e) {
          parsedMessage = (org.beangle.security.session.protobuf.Model.Account) e.getUnfinishedMessage();
          throw e.unwrapIOException();
        } finally {
          if (parsedMessage != null) {
            mergeFrom(parsedMessage);
          }
        }
        return this;
      }
      private int bitField0_;

      private java.lang.Object name_ = "";
      /**
       * <code>string name = 1;</code>
       */
      public java.lang.String getName() {
        java.lang.Object ref = name_;
        if (!(ref instanceof java.lang.String)) {
          com.google.protobuf.ByteString bs =
              (com.google.protobuf.ByteString) ref;
          java.lang.String s = bs.toStringUtf8();
          name_ = s;
          return s;
        } else {
          return (java.lang.String) ref;
        }
      }
      /**
       * <code>string name = 1;</code>
       */
      public com.google.protobuf.ByteString
          getNameBytes() {
        java.lang.Object ref = name_;
        if (ref instanceof String) {
          com.google.protobuf.ByteString b =
              com.google.protobuf.ByteString.copyFromUtf8(
                  (java.lang.String) ref);
          name_ = b;
          return b;
        } else {
          return (com.google.protobuf.ByteString) ref;
        }
      }
      /**
       * <code>string name = 1;</code>
       */
      public Builder setName(
          java.lang.String value) {
        if (value == null) {
    throw new NullPointerException();
  }

        name_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>string name = 1;</code>
       */
      public Builder clearName() {

        name_ = getDefaultInstance().getName();
        onChanged();
        return this;
      }
      /**
       * <code>string name = 1;</code>
       */
      public Builder setNameBytes(
          com.google.protobuf.ByteString value) {
        if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);

        name_ = value;
        onChanged();
        return this;
      }

      private java.lang.Object description_ = "";
      /**
       * <code>string description = 2;</code>
       */
      public java.lang.String getDescription() {
        java.lang.Object ref = description_;
        if (!(ref instanceof java.lang.String)) {
          com.google.protobuf.ByteString bs =
              (com.google.protobuf.ByteString) ref;
          java.lang.String s = bs.toStringUtf8();
          description_ = s;
          return s;
        } else {
          return (java.lang.String) ref;
        }
      }
      /**
       * <code>string description = 2;</code>
       */
      public com.google.protobuf.ByteString
          getDescriptionBytes() {
        java.lang.Object ref = description_;
        if (ref instanceof String) {
          com.google.protobuf.ByteString b =
              com.google.protobuf.ByteString.copyFromUtf8(
                  (java.lang.String) ref);
          description_ = b;
          return b;
        } else {
          return (com.google.protobuf.ByteString) ref;
        }
      }
      /**
       * <code>string description = 2;</code>
       */
      public Builder setDescription(
          java.lang.String value) {
        if (value == null) {
    throw new NullPointerException();
  }

        description_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>string description = 2;</code>
       */
      public Builder clearDescription() {

        description_ = getDefaultInstance().getDescription();
        onChanged();
        return this;
      }
      /**
       * <code>string description = 2;</code>
       */
      public Builder setDescriptionBytes(
          com.google.protobuf.ByteString value) {
        if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);

        description_ = value;
        onChanged();
        return this;
      }

      private java.lang.Object remoteToken_ = "";
      /**
       * <code>string remoteToken = 3;</code>
       */
      public java.lang.String getRemoteToken() {
        java.lang.Object ref = remoteToken_;
        if (!(ref instanceof java.lang.String)) {
          com.google.protobuf.ByteString bs =
              (com.google.protobuf.ByteString) ref;
          java.lang.String s = bs.toStringUtf8();
          remoteToken_ = s;
          return s;
        } else {
          return (java.lang.String) ref;
        }
      }
      /**
       * <code>string remoteToken = 3;</code>
       */
      public com.google.protobuf.ByteString
          getRemoteTokenBytes() {
        java.lang.Object ref = remoteToken_;
        if (ref instanceof String) {
          com.google.protobuf.ByteString b =
              com.google.protobuf.ByteString.copyFromUtf8(
                  (java.lang.String) ref);
          remoteToken_ = b;
          return b;
        } else {
          return (com.google.protobuf.ByteString) ref;
        }
      }
      /**
       * <code>string remoteToken = 3;</code>
       */
      public Builder setRemoteToken(
          java.lang.String value) {
        if (value == null) {
    throw new NullPointerException();
  }

        remoteToken_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>string remoteToken = 3;</code>
       */
      public Builder clearRemoteToken() {

        remoteToken_ = getDefaultInstance().getRemoteToken();
        onChanged();
        return this;
      }
      /**
       * <code>string remoteToken = 3;</code>
       */
      public Builder setRemoteTokenBytes(
          com.google.protobuf.ByteString value) {
        if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);

        remoteToken_ = value;
        onChanged();
        return this;
      }

      private int status_ ;
      /**
       * <code>int32 status = 4;</code>
       */
      public int getStatus() {
        return status_;
      }
      /**
       * <code>int32 status = 4;</code>
       */
      public Builder setStatus(int value) {

        status_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>int32 status = 4;</code>
       */
      public Builder clearStatus() {

        status_ = 0;
        onChanged();
        return this;
      }

      private java.lang.Object authorities_ = "";
      /**
       * <code>string authorities = 5;</code>
       */
      public java.lang.String getAuthorities() {
        java.lang.Object ref = authorities_;
        if (!(ref instanceof java.lang.String)) {
          com.google.protobuf.ByteString bs =
              (com.google.protobuf.ByteString) ref;
          java.lang.String s = bs.toStringUtf8();
          authorities_ = s;
          return s;
        } else {
          return (java.lang.String) ref;
        }
      }
      /**
       * <code>string authorities = 5;</code>
       */
      public com.google.protobuf.ByteString
          getAuthoritiesBytes() {
        java.lang.Object ref = authorities_;
        if (ref instanceof String) {
          com.google.protobuf.ByteString b =
              com.google.protobuf.ByteString.copyFromUtf8(
                  (java.lang.String) ref);
          authorities_ = b;
          return b;
        } else {
          return (com.google.protobuf.ByteString) ref;
        }
      }
      /**
       * <code>string authorities = 5;</code>
       */
      public Builder setAuthorities(
          java.lang.String value) {
        if (value == null) {
    throw new NullPointerException();
  }

        authorities_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>string authorities = 5;</code>
       */
      public Builder clearAuthorities() {

        authorities_ = getDefaultInstance().getAuthorities();
        onChanged();
        return this;
      }
      /**
       * <code>string authorities = 5;</code>
       */
      public Builder setAuthoritiesBytes(
          com.google.protobuf.ByteString value) {
        if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);

        authorities_ = value;
        onChanged();
        return this;
      }

      private java.lang.Object permissions_ = "";
      /**
       * <code>string permissions = 6;</code>
       */
      public java.lang.String getPermissions() {
        java.lang.Object ref = permissions_;
        if (!(ref instanceof java.lang.String)) {
          com.google.protobuf.ByteString bs =
              (com.google.protobuf.ByteString) ref;
          java.lang.String s = bs.toStringUtf8();
          permissions_ = s;
          return s;
        } else {
          return (java.lang.String) ref;
        }
      }
      /**
       * <code>string permissions = 6;</code>
       */
      public com.google.protobuf.ByteString
          getPermissionsBytes() {
        java.lang.Object ref = permissions_;
        if (ref instanceof String) {
          com.google.protobuf.ByteString b =
              com.google.protobuf.ByteString.copyFromUtf8(
                  (java.lang.String) ref);
          permissions_ = b;
          return b;
        } else {
          return (com.google.protobuf.ByteString) ref;
        }
      }
      /**
       * <code>string permissions = 6;</code>
       */
      public Builder setPermissions(
          java.lang.String value) {
        if (value == null) {
    throw new NullPointerException();
  }

        permissions_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>string permissions = 6;</code>
       */
      public Builder clearPermissions() {

        permissions_ = getDefaultInstance().getPermissions();
        onChanged();
        return this;
      }
      /**
       * <code>string permissions = 6;</code>
       */
      public Builder setPermissionsBytes(
          com.google.protobuf.ByteString value) {
        if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);

        permissions_ = value;
        onChanged();
        return this;
      }

      private com.google.protobuf.MapField<
          java.lang.String, java.lang.String> details_;
      private com.google.protobuf.MapField<java.lang.String, java.lang.String>
      internalGetDetails() {
        if (details_ == null) {
          return com.google.protobuf.MapField.emptyMapField(
              DetailsDefaultEntryHolder.defaultEntry);
        }
        return details_;
      }
      private com.google.protobuf.MapField<java.lang.String, java.lang.String>
      internalGetMutableDetails() {
        onChanged();;
        if (details_ == null) {
          details_ = com.google.protobuf.MapField.newMapField(
              DetailsDefaultEntryHolder.defaultEntry);
        }
        if (!details_.isMutable()) {
          details_ = details_.copy();
        }
        return details_;
      }

      public int getDetailsCount() {
        return internalGetDetails().getMap().size();
      }
      /**
       * <code>map&lt;string, string&gt; details = 7;</code>
       */

      public boolean containsDetails(
          java.lang.String key) {
        if (key == null) { throw new java.lang.NullPointerException(); }
        return internalGetDetails().getMap().containsKey(key);
      }
      /**
       * Use {@link #getDetailsMap()} instead.
       */
      @java.lang.Deprecated
      public java.util.Map<java.lang.String, java.lang.String> getDetails() {
        return getDetailsMap();
      }
      /**
       * <code>map&lt;string, string&gt; details = 7;</code>
       */

      public java.util.Map<java.lang.String, java.lang.String> getDetailsMap() {
        return internalGetDetails().getMap();
      }
      /**
       * <code>map&lt;string, string&gt; details = 7;</code>
       */

      public java.lang.String getDetailsOrDefault(
          java.lang.String key,
          java.lang.String defaultValue) {
        if (key == null) { throw new java.lang.NullPointerException(); }
        java.util.Map<java.lang.String, java.lang.String> map =
            internalGetDetails().getMap();
        return map.containsKey(key) ? map.get(key) : defaultValue;
      }
      /**
       * <code>map&lt;string, string&gt; details = 7;</code>
       */

      public java.lang.String getDetailsOrThrow(
          java.lang.String key) {
        if (key == null) { throw new java.lang.NullPointerException(); }
        java.util.Map<java.lang.String, java.lang.String> map =
            internalGetDetails().getMap();
        if (!map.containsKey(key)) {
          throw new java.lang.IllegalArgumentException();
        }
        return map.get(key);
      }

      public Builder clearDetails() {
        internalGetMutableDetails().getMutableMap()
            .clear();
        return this;
      }
      /**
       * <code>map&lt;string, string&gt; details = 7;</code>
       */

      public Builder removeDetails(
          java.lang.String key) {
        if (key == null) { throw new java.lang.NullPointerException(); }
        internalGetMutableDetails().getMutableMap()
            .remove(key);
        return this;
      }
      /**
       * Use alternate mutation accessors instead.
       */
      @java.lang.Deprecated
      public java.util.Map<java.lang.String, java.lang.String>
      getMutableDetails() {
        return internalGetMutableDetails().getMutableMap();
      }
      /**
       * <code>map&lt;string, string&gt; details = 7;</code>
       */
      public Builder putDetails(
          java.lang.String key,
          java.lang.String value) {
        if (key == null) { throw new java.lang.NullPointerException(); }
        if (value == null) { throw new java.lang.NullPointerException(); }
        internalGetMutableDetails().getMutableMap()
            .put(key, value);
        return this;
      }
      /**
       * <code>map&lt;string, string&gt; details = 7;</code>
       */

      public Builder putAllDetails(
          java.util.Map<java.lang.String, java.lang.String> values) {
        internalGetMutableDetails().getMutableMap()
            .putAll(values);
        return this;
      }
      public final Builder setUnknownFields(
          final com.google.protobuf.UnknownFieldSet unknownFields) {
        return super.setUnknownFieldsProto3(unknownFields);
      }

      public final Builder mergeUnknownFields(
          final com.google.protobuf.UnknownFieldSet unknownFields) {
        return super.mergeUnknownFields(unknownFields);
      }

      // @@protoc_insertion_point(builder_scope:Account)
    }

    // @@protoc_insertion_point(class_scope:Account)
    private static final org.beangle.security.session.protobuf.Model.Account DEFAULT_INSTANCE;
    static {
      DEFAULT_INSTANCE = new org.beangle.security.session.protobuf.Model.Account();
    }

    public static org.beangle.security.session.protobuf.Model.Account getDefaultInstance() {
      return DEFAULT_INSTANCE;
    }

    private static final com.google.protobuf.Parser<Account>
        PARSER = new com.google.protobuf.AbstractParser<Account>() {
      public Account parsePartialFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws com.google.protobuf.InvalidProtocolBufferException {
        return new Account(input, extensionRegistry);
      }
    };

    public static com.google.protobuf.Parser<Account> parser() {
      return PARSER;
    }

    @java.lang.Override
    public com.google.protobuf.Parser<Account> getParserForType() {
      return PARSER;
    }

    public org.beangle.security.session.protobuf.Model.Account getDefaultInstanceForType() {
      return DEFAULT_INSTANCE;
    }

  }

  public interface AgentOrBuilder extends
      // @@protoc_insertion_point(interface_extends:Agent)
      com.google.protobuf.MessageOrBuilder {

    /**
     * <code>string name = 1;</code>
     */
    java.lang.String getName();
    /**
     * <code>string name = 1;</code>
     */
    com.google.protobuf.ByteString
        getNameBytes();

    /**
     * <code>string ip = 2;</code>
     */
    java.lang.String getIp();
    /**
     * <code>string ip = 2;</code>
     */
    com.google.protobuf.ByteString
        getIpBytes();

    /**
     * <code>string os = 3;</code>
     */
    java.lang.String getOs();
    /**
     * <code>string os = 3;</code>
     */
    com.google.protobuf.ByteString
        getOsBytes();
  }
  /**
   * Protobuf type {@code Agent}
   */
  public  static final class Agent extends
      com.google.protobuf.GeneratedMessageV3 implements
      // @@protoc_insertion_point(message_implements:Agent)
      AgentOrBuilder {
  private static final long serialVersionUID = 0L;
    // Use Agent.newBuilder() to construct.
    private Agent(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
      super(builder);
    }
    private Agent() {
      name_ = "";
      ip_ = "";
      os_ = "";
    }

    @java.lang.Override
    public final com.google.protobuf.UnknownFieldSet
    getUnknownFields() {
      return this.unknownFields;
    }
    private Agent(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      this();
      if (extensionRegistry == null) {
        throw new java.lang.NullPointerException();
      }
      int mutable_bitField0_ = 0;
      com.google.protobuf.UnknownFieldSet.Builder unknownFields =
          com.google.protobuf.UnknownFieldSet.newBuilder();
      try {
        boolean done = false;
        while (!done) {
          int tag = input.readTag();
          switch (tag) {
            case 0:
              done = true;
              break;
            default: {
              if (!parseUnknownFieldProto3(
                  input, unknownFields, extensionRegistry, tag)) {
                done = true;
              }
              break;
            }
            case 10: {
              java.lang.String s = input.readStringRequireUtf8();

              name_ = s;
              break;
            }
            case 18: {
              java.lang.String s = input.readStringRequireUtf8();

              ip_ = s;
              break;
            }
            case 26: {
              java.lang.String s = input.readStringRequireUtf8();

              os_ = s;
              break;
            }
          }
        }
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        throw e.setUnfinishedMessage(this);
      } catch (java.io.IOException e) {
        throw new com.google.protobuf.InvalidProtocolBufferException(
            e).setUnfinishedMessage(this);
      } finally {
        this.unknownFields = unknownFields.build();
        makeExtensionsImmutable();
      }
    }
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return org.beangle.security.session.protobuf.Model.internal_static_Agent_descriptor;
    }

    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return org.beangle.security.session.protobuf.Model.internal_static_Agent_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              org.beangle.security.session.protobuf.Model.Agent.class, org.beangle.security.session.protobuf.Model.Agent.Builder.class);
    }

    public static final int NAME_FIELD_NUMBER = 1;
    private volatile java.lang.Object name_;
    /**
     * <code>string name = 1;</code>
     */
    public java.lang.String getName() {
      java.lang.Object ref = name_;
      if (ref instanceof java.lang.String) {
        return (java.lang.String) ref;
      } else {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        name_ = s;
        return s;
      }
    }
    /**
     * <code>string name = 1;</code>
     */
    public com.google.protobuf.ByteString
        getNameBytes() {
      java.lang.Object ref = name_;
      if (ref instanceof java.lang.String) {
        com.google.protobuf.ByteString b =
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        name_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }

    public static final int IP_FIELD_NUMBER = 2;
    private volatile java.lang.Object ip_;
    /**
     * <code>string ip = 2;</code>
     */
    public java.lang.String getIp() {
      java.lang.Object ref = ip_;
      if (ref instanceof java.lang.String) {
        return (java.lang.String) ref;
      } else {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        ip_ = s;
        return s;
      }
    }
    /**
     * <code>string ip = 2;</code>
     */
    public com.google.protobuf.ByteString
        getIpBytes() {
      java.lang.Object ref = ip_;
      if (ref instanceof java.lang.String) {
        com.google.protobuf.ByteString b =
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        ip_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }

    public static final int OS_FIELD_NUMBER = 3;
    private volatile java.lang.Object os_;
    /**
     * <code>string os = 3;</code>
     */
    public java.lang.String getOs() {
      java.lang.Object ref = os_;
      if (ref instanceof java.lang.String) {
        return (java.lang.String) ref;
      } else {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        os_ = s;
        return s;
      }
    }
    /**
     * <code>string os = 3;</code>
     */
    public com.google.protobuf.ByteString
        getOsBytes() {
      java.lang.Object ref = os_;
      if (ref instanceof java.lang.String) {
        com.google.protobuf.ByteString b =
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        os_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }

    private byte memoizedIsInitialized = -1;
    public final boolean isInitialized() {
      byte isInitialized = memoizedIsInitialized;
      if (isInitialized == 1) return true;
      if (isInitialized == 0) return false;

      memoizedIsInitialized = 1;
      return true;
    }

    public void writeTo(com.google.protobuf.CodedOutputStream output)
                        throws java.io.IOException {
      if (!getNameBytes().isEmpty()) {
        com.google.protobuf.GeneratedMessageV3.writeString(output, 1, name_);
      }
      if (!getIpBytes().isEmpty()) {
        com.google.protobuf.GeneratedMessageV3.writeString(output, 2, ip_);
      }
      if (!getOsBytes().isEmpty()) {
        com.google.protobuf.GeneratedMessageV3.writeString(output, 3, os_);
      }
      unknownFields.writeTo(output);
    }

    public int getSerializedSize() {
      int size = memoizedSize;
      if (size != -1) return size;

      size = 0;
      if (!getNameBytes().isEmpty()) {
        size += com.google.protobuf.GeneratedMessageV3.computeStringSize(1, name_);
      }
      if (!getIpBytes().isEmpty()) {
        size += com.google.protobuf.GeneratedMessageV3.computeStringSize(2, ip_);
      }
      if (!getOsBytes().isEmpty()) {
        size += com.google.protobuf.GeneratedMessageV3.computeStringSize(3, os_);
      }
      size += unknownFields.getSerializedSize();
      memoizedSize = size;
      return size;
    }

    @java.lang.Override
    public boolean equals(final java.lang.Object obj) {
      if (obj == this) {
       return true;
      }
      if (!(obj instanceof org.beangle.security.session.protobuf.Model.Agent)) {
        return super.equals(obj);
      }
      org.beangle.security.session.protobuf.Model.Agent other = (org.beangle.security.session.protobuf.Model.Agent) obj;

      boolean result = true;
      result = result && getName()
          .equals(other.getName());
      result = result && getIp()
          .equals(other.getIp());
      result = result && getOs()
          .equals(other.getOs());
      result = result && unknownFields.equals(other.unknownFields);
      return result;
    }

    @java.lang.Override
    public int hashCode() {
      if (memoizedHashCode != 0) {
        return memoizedHashCode;
      }
      int hash = 41;
      hash = (19 * hash) + getDescriptor().hashCode();
      hash = (37 * hash) + NAME_FIELD_NUMBER;
      hash = (53 * hash) + getName().hashCode();
      hash = (37 * hash) + IP_FIELD_NUMBER;
      hash = (53 * hash) + getIp().hashCode();
      hash = (37 * hash) + OS_FIELD_NUMBER;
      hash = (53 * hash) + getOs().hashCode();
      hash = (29 * hash) + unknownFields.hashCode();
      memoizedHashCode = hash;
      return hash;
    }

    public static org.beangle.security.session.protobuf.Model.Agent parseFrom(
        java.nio.ByteBuffer data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static org.beangle.security.session.protobuf.Model.Agent parseFrom(
        java.nio.ByteBuffer data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static org.beangle.security.session.protobuf.Model.Agent parseFrom(
        com.google.protobuf.ByteString data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static org.beangle.security.session.protobuf.Model.Agent parseFrom(
        com.google.protobuf.ByteString data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static org.beangle.security.session.protobuf.Model.Agent parseFrom(byte[] data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static org.beangle.security.session.protobuf.Model.Agent parseFrom(
        byte[] data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static org.beangle.security.session.protobuf.Model.Agent parseFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static org.beangle.security.session.protobuf.Model.Agent parseFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }
    public static org.beangle.security.session.protobuf.Model.Agent parseDelimitedFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input);
    }
    public static org.beangle.security.session.protobuf.Model.Agent parseDelimitedFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
    }
    public static org.beangle.security.session.protobuf.Model.Agent parseFrom(
        com.google.protobuf.CodedInputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static org.beangle.security.session.protobuf.Model.Agent parseFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }

    public Builder newBuilderForType() { return newBuilder(); }
    public static Builder newBuilder() {
      return DEFAULT_INSTANCE.toBuilder();
    }
    public static Builder newBuilder(org.beangle.security.session.protobuf.Model.Agent prototype) {
      return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
    }
    public Builder toBuilder() {
      return this == DEFAULT_INSTANCE
          ? new Builder() : new Builder().mergeFrom(this);
    }

    @java.lang.Override
    protected Builder newBuilderForType(
        com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
      Builder builder = new Builder(parent);
      return builder;
    }
    /**
     * Protobuf type {@code Agent}
     */
    public static final class Builder extends
        com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
        // @@protoc_insertion_point(builder_implements:Agent)
        org.beangle.security.session.protobuf.Model.AgentOrBuilder {
      public static final com.google.protobuf.Descriptors.Descriptor
          getDescriptor() {
        return org.beangle.security.session.protobuf.Model.internal_static_Agent_descriptor;
      }

      protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
          internalGetFieldAccessorTable() {
        return org.beangle.security.session.protobuf.Model.internal_static_Agent_fieldAccessorTable
            .ensureFieldAccessorsInitialized(
                org.beangle.security.session.protobuf.Model.Agent.class, org.beangle.security.session.protobuf.Model.Agent.Builder.class);
      }

      // Construct using org.beangle.security.session.protobuf.Model.Agent.newBuilder()
      private Builder() {
        maybeForceBuilderInitialization();
      }

      private Builder(
          com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
        super(parent);
        maybeForceBuilderInitialization();
      }
      private void maybeForceBuilderInitialization() {
        if (com.google.protobuf.GeneratedMessageV3
                .alwaysUseFieldBuilders) {
        }
      }
      public Builder clear() {
        super.clear();
        name_ = "";

        ip_ = "";

        os_ = "";

        return this;
      }

      public com.google.protobuf.Descriptors.Descriptor
          getDescriptorForType() {
        return org.beangle.security.session.protobuf.Model.internal_static_Agent_descriptor;
      }

      public org.beangle.security.session.protobuf.Model.Agent getDefaultInstanceForType() {
        return org.beangle.security.session.protobuf.Model.Agent.getDefaultInstance();
      }

      public org.beangle.security.session.protobuf.Model.Agent build() {
        org.beangle.security.session.protobuf.Model.Agent result = buildPartial();
        if (!result.isInitialized()) {
          throw newUninitializedMessageException(result);
        }
        return result;
      }

      public org.beangle.security.session.protobuf.Model.Agent buildPartial() {
        org.beangle.security.session.protobuf.Model.Agent result = new org.beangle.security.session.protobuf.Model.Agent(this);
        result.name_ = name_;
        result.ip_ = ip_;
        result.os_ = os_;
        onBuilt();
        return result;
      }

      public Builder clone() {
        return (Builder) super.clone();
      }
      public Builder setField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          java.lang.Object value) {
        return (Builder) super.setField(field, value);
      }
      public Builder clearField(
          com.google.protobuf.Descriptors.FieldDescriptor field) {
        return (Builder) super.clearField(field);
      }
      public Builder clearOneof(
          com.google.protobuf.Descriptors.OneofDescriptor oneof) {
        return (Builder) super.clearOneof(oneof);
      }
      public Builder setRepeatedField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          int index, java.lang.Object value) {
        return (Builder) super.setRepeatedField(field, index, value);
      }
      public Builder addRepeatedField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          java.lang.Object value) {
        return (Builder) super.addRepeatedField(field, value);
      }
      public Builder mergeFrom(com.google.protobuf.Message other) {
        if (other instanceof org.beangle.security.session.protobuf.Model.Agent) {
          return mergeFrom((org.beangle.security.session.protobuf.Model.Agent)other);
        } else {
          super.mergeFrom(other);
          return this;
        }
      }

      public Builder mergeFrom(org.beangle.security.session.protobuf.Model.Agent other) {
        if (other == org.beangle.security.session.protobuf.Model.Agent.getDefaultInstance()) return this;
        if (!other.getName().isEmpty()) {
          name_ = other.name_;
          onChanged();
        }
        if (!other.getIp().isEmpty()) {
          ip_ = other.ip_;
          onChanged();
        }
        if (!other.getOs().isEmpty()) {
          os_ = other.os_;
          onChanged();
        }
        this.mergeUnknownFields(other.unknownFields);
        onChanged();
        return this;
      }

      public final boolean isInitialized() {
        return true;
      }

      public Builder mergeFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws java.io.IOException {
        org.beangle.security.session.protobuf.Model.Agent parsedMessage = null;
        try {
          parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
        } catch (com.google.protobuf.InvalidProtocolBufferException e) {
          parsedMessage = (org.beangle.security.session.protobuf.Model.Agent) e.getUnfinishedMessage();
          throw e.unwrapIOException();
        } finally {
          if (parsedMessage != null) {
            mergeFrom(parsedMessage);
          }
        }
        return this;
      }

      private java.lang.Object name_ = "";
      /**
       * <code>string name = 1;</code>
       */
      public java.lang.String getName() {
        java.lang.Object ref = name_;
        if (!(ref instanceof java.lang.String)) {
          com.google.protobuf.ByteString bs =
              (com.google.protobuf.ByteString) ref;
          java.lang.String s = bs.toStringUtf8();
          name_ = s;
          return s;
        } else {
          return (java.lang.String) ref;
        }
      }
      /**
       * <code>string name = 1;</code>
       */
      public com.google.protobuf.ByteString
          getNameBytes() {
        java.lang.Object ref = name_;
        if (ref instanceof String) {
          com.google.protobuf.ByteString b =
              com.google.protobuf.ByteString.copyFromUtf8(
                  (java.lang.String) ref);
          name_ = b;
          return b;
        } else {
          return (com.google.protobuf.ByteString) ref;
        }
      }
      /**
       * <code>string name = 1;</code>
       */
      public Builder setName(
          java.lang.String value) {
        if (value == null) {
    throw new NullPointerException();
  }

        name_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>string name = 1;</code>
       */
      public Builder clearName() {

        name_ = getDefaultInstance().getName();
        onChanged();
        return this;
      }
      /**
       * <code>string name = 1;</code>
       */
      public Builder setNameBytes(
          com.google.protobuf.ByteString value) {
        if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);

        name_ = value;
        onChanged();
        return this;
      }

      private java.lang.Object ip_ = "";
      /**
       * <code>string ip = 2;</code>
       */
      public java.lang.String getIp() {
        java.lang.Object ref = ip_;
        if (!(ref instanceof java.lang.String)) {
          com.google.protobuf.ByteString bs =
              (com.google.protobuf.ByteString) ref;
          java.lang.String s = bs.toStringUtf8();
          ip_ = s;
          return s;
        } else {
          return (java.lang.String) ref;
        }
      }
      /**
       * <code>string ip = 2;</code>
       */
      public com.google.protobuf.ByteString
          getIpBytes() {
        java.lang.Object ref = ip_;
        if (ref instanceof String) {
          com.google.protobuf.ByteString b =
              com.google.protobuf.ByteString.copyFromUtf8(
                  (java.lang.String) ref);
          ip_ = b;
          return b;
        } else {
          return (com.google.protobuf.ByteString) ref;
        }
      }
      /**
       * <code>string ip = 2;</code>
       */
      public Builder setIp(
          java.lang.String value) {
        if (value == null) {
    throw new NullPointerException();
  }

        ip_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>string ip = 2;</code>
       */
      public Builder clearIp() {

        ip_ = getDefaultInstance().getIp();
        onChanged();
        return this;
      }
      /**
       * <code>string ip = 2;</code>
       */
      public Builder setIpBytes(
          com.google.protobuf.ByteString value) {
        if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);

        ip_ = value;
        onChanged();
        return this;
      }

      private java.lang.Object os_ = "";
      /**
       * <code>string os = 3;</code>
       */
      public java.lang.String getOs() {
        java.lang.Object ref = os_;
        if (!(ref instanceof java.lang.String)) {
          com.google.protobuf.ByteString bs =
              (com.google.protobuf.ByteString) ref;
          java.lang.String s = bs.toStringUtf8();
          os_ = s;
          return s;
        } else {
          return (java.lang.String) ref;
        }
      }
      /**
       * <code>string os = 3;</code>
       */
      public com.google.protobuf.ByteString
          getOsBytes() {
        java.lang.Object ref = os_;
        if (ref instanceof String) {
          com.google.protobuf.ByteString b =
              com.google.protobuf.ByteString.copyFromUtf8(
                  (java.lang.String) ref);
          os_ = b;
          return b;
        } else {
          return (com.google.protobuf.ByteString) ref;
        }
      }
      /**
       * <code>string os = 3;</code>
       */
      public Builder setOs(
          java.lang.String value) {
        if (value == null) {
    throw new NullPointerException();
  }

        os_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>string os = 3;</code>
       */
      public Builder clearOs() {

        os_ = getDefaultInstance().getOs();
        onChanged();
        return this;
      }
      /**
       * <code>string os = 3;</code>
       */
      public Builder setOsBytes(
          com.google.protobuf.ByteString value) {
        if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);

        os_ = value;
        onChanged();
        return this;
      }
      public final Builder setUnknownFields(
          final com.google.protobuf.UnknownFieldSet unknownFields) {
        return super.setUnknownFieldsProto3(unknownFields);
      }

      public final Builder mergeUnknownFields(
          final com.google.protobuf.UnknownFieldSet unknownFields) {
        return super.mergeUnknownFields(unknownFields);
      }

      // @@protoc_insertion_point(builder_scope:Agent)
    }

    // @@protoc_insertion_point(class_scope:Agent)
    private static final org.beangle.security.session.protobuf.Model.Agent DEFAULT_INSTANCE;
    static {
      DEFAULT_INSTANCE = new org.beangle.security.session.protobuf.Model.Agent();
    }

    public static org.beangle.security.session.protobuf.Model.Agent getDefaultInstance() {
      return DEFAULT_INSTANCE;
    }

    private static final com.google.protobuf.Parser<Agent>
        PARSER = new com.google.protobuf.AbstractParser<Agent>() {
      public Agent parsePartialFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws com.google.protobuf.InvalidProtocolBufferException {
        return new Agent(input, extensionRegistry);
      }
    };

    public static com.google.protobuf.Parser<Agent> parser() {
      return PARSER;
    }

    @java.lang.Override
    public com.google.protobuf.Parser<Agent> getParserForType() {
      return PARSER;
    }

    public org.beangle.security.session.protobuf.Model.Agent getDefaultInstanceForType() {
      return DEFAULT_INSTANCE;
    }

  }

  public interface SessionOrBuilder extends
      // @@protoc_insertion_point(interface_extends:Session)
      com.google.protobuf.MessageOrBuilder {

    /**
     * <code>string id = 1;</code>
     */
    java.lang.String getId();
    /**
     * <code>string id = 1;</code>
     */
    com.google.protobuf.ByteString
        getIdBytes();

    /**
     * <code>.Account principal = 2;</code>
     */
    boolean hasPrincipal();
    /**
     * <code>.Account principal = 2;</code>
     */
    org.beangle.security.session.protobuf.Model.Account getPrincipal();
    /**
     * <code>.Account principal = 2;</code>
     */
    org.beangle.security.session.protobuf.Model.AccountOrBuilder getPrincipalOrBuilder();

    /**
     * <code>int64 loginAt = 3;</code>
     */
    long getLoginAt();

    /**
     * <code>int64 lastAccessAt = 4;</code>
     */
    long getLastAccessAt();

    /**
     * <code>.Agent agent = 5;</code>
     */
    boolean hasAgent();
    /**
     * <code>.Agent agent = 5;</code>
     */
    org.beangle.security.session.protobuf.Model.Agent getAgent();
    /**
     * <code>.Agent agent = 5;</code>
     */
    org.beangle.security.session.protobuf.Model.AgentOrBuilder getAgentOrBuilder();
  }
  /**
   * Protobuf type {@code Session}
   */
  public  static final class Session extends
      com.google.protobuf.GeneratedMessageV3 implements
      // @@protoc_insertion_point(message_implements:Session)
      SessionOrBuilder {
  private static final long serialVersionUID = 0L;
    // Use Session.newBuilder() to construct.
    private Session(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
      super(builder);
    }
    private Session() {
      id_ = "";
      loginAt_ = 0L;
      lastAccessAt_ = 0L;
    }

    @java.lang.Override
    public final com.google.protobuf.UnknownFieldSet
    getUnknownFields() {
      return this.unknownFields;
    }
    private Session(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      this();
      if (extensionRegistry == null) {
        throw new java.lang.NullPointerException();
      }
      int mutable_bitField0_ = 0;
      com.google.protobuf.UnknownFieldSet.Builder unknownFields =
          com.google.protobuf.UnknownFieldSet.newBuilder();
      try {
        boolean done = false;
        while (!done) {
          int tag = input.readTag();
          switch (tag) {
            case 0:
              done = true;
              break;
            default: {
              if (!parseUnknownFieldProto3(
                  input, unknownFields, extensionRegistry, tag)) {
                done = true;
              }
              break;
            }
            case 10: {
              java.lang.String s = input.readStringRequireUtf8();

              id_ = s;
              break;
            }
            case 18: {
              org.beangle.security.session.protobuf.Model.Account.Builder subBuilder = null;
              if (principal_ != null) {
                subBuilder = principal_.toBuilder();
              }
              principal_ = input.readMessage(org.beangle.security.session.protobuf.Model.Account.parser(), extensionRegistry);
              if (subBuilder != null) {
                subBuilder.mergeFrom(principal_);
                principal_ = subBuilder.buildPartial();
              }

              break;
            }
            case 24: {

              loginAt_ = input.readInt64();
              break;
            }
            case 32: {

              lastAccessAt_ = input.readInt64();
              break;
            }
            case 42: {
              org.beangle.security.session.protobuf.Model.Agent.Builder subBuilder = null;
              if (agent_ != null) {
                subBuilder = agent_.toBuilder();
              }
              agent_ = input.readMessage(org.beangle.security.session.protobuf.Model.Agent.parser(), extensionRegistry);
              if (subBuilder != null) {
                subBuilder.mergeFrom(agent_);
                agent_ = subBuilder.buildPartial();
              }

              break;
            }
          }
        }
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        throw e.setUnfinishedMessage(this);
      } catch (java.io.IOException e) {
        throw new com.google.protobuf.InvalidProtocolBufferException(
            e).setUnfinishedMessage(this);
      } finally {
        this.unknownFields = unknownFields.build();
        makeExtensionsImmutable();
      }
    }
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return org.beangle.security.session.protobuf.Model.internal_static_Session_descriptor;
    }

    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return org.beangle.security.session.protobuf.Model.internal_static_Session_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              org.beangle.security.session.protobuf.Model.Session.class, org.beangle.security.session.protobuf.Model.Session.Builder.class);
    }

    public static final int ID_FIELD_NUMBER = 1;
    private volatile java.lang.Object id_;
    /**
     * <code>string id = 1;</code>
     */
    public java.lang.String getId() {
      java.lang.Object ref = id_;
      if (ref instanceof java.lang.String) {
        return (java.lang.String) ref;
      } else {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        id_ = s;
        return s;
      }
    }
    /**
     * <code>string id = 1;</code>
     */
    public com.google.protobuf.ByteString
        getIdBytes() {
      java.lang.Object ref = id_;
      if (ref instanceof java.lang.String) {
        com.google.protobuf.ByteString b =
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        id_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }

    public static final int PRINCIPAL_FIELD_NUMBER = 2;
    private org.beangle.security.session.protobuf.Model.Account principal_;
    /**
     * <code>.Account principal = 2;</code>
     */
    public boolean hasPrincipal() {
      return principal_ != null;
    }
    /**
     * <code>.Account principal = 2;</code>
     */
    public org.beangle.security.session.protobuf.Model.Account getPrincipal() {
      return principal_ == null ? org.beangle.security.session.protobuf.Model.Account.getDefaultInstance() : principal_;
    }
    /**
     * <code>.Account principal = 2;</code>
     */
    public org.beangle.security.session.protobuf.Model.AccountOrBuilder getPrincipalOrBuilder() {
      return getPrincipal();
    }

    public static final int LOGINAT_FIELD_NUMBER = 3;
    private long loginAt_;
    /**
     * <code>int64 loginAt = 3;</code>
     */
    public long getLoginAt() {
      return loginAt_;
    }

    public static final int LASTACCESSAT_FIELD_NUMBER = 4;
    private long lastAccessAt_;
    /**
     * <code>int64 lastAccessAt = 4;</code>
     */
    public long getLastAccessAt() {
      return lastAccessAt_;
    }

    public static final int AGENT_FIELD_NUMBER = 5;
    private org.beangle.security.session.protobuf.Model.Agent agent_;
    /**
     * <code>.Agent agent = 5;</code>
     */
    public boolean hasAgent() {
      return agent_ != null;
    }
    /**
     * <code>.Agent agent = 5;</code>
     */
    public org.beangle.security.session.protobuf.Model.Agent getAgent() {
      return agent_ == null ? org.beangle.security.session.protobuf.Model.Agent.getDefaultInstance() : agent_;
    }
    /**
     * <code>.Agent agent = 5;</code>
     */
    public org.beangle.security.session.protobuf.Model.AgentOrBuilder getAgentOrBuilder() {
      return getAgent();
    }

    private byte memoizedIsInitialized = -1;
    public final boolean isInitialized() {
      byte isInitialized = memoizedIsInitialized;
      if (isInitialized == 1) return true;
      if (isInitialized == 0) return false;

      memoizedIsInitialized = 1;
      return true;
    }

    public void writeTo(com.google.protobuf.CodedOutputStream output)
                        throws java.io.IOException {
      if (!getIdBytes().isEmpty()) {
        com.google.protobuf.GeneratedMessageV3.writeString(output, 1, id_);
      }
      if (principal_ != null) {
        output.writeMessage(2, getPrincipal());
      }
      if (loginAt_ != 0L) {
        output.writeInt64(3, loginAt_);
      }
      if (lastAccessAt_ != 0L) {
        output.writeInt64(4, lastAccessAt_);
      }
      if (agent_ != null) {
        output.writeMessage(5, getAgent());
      }
      unknownFields.writeTo(output);
    }

    public int getSerializedSize() {
      int size = memoizedSize;
      if (size != -1) return size;

      size = 0;
      if (!getIdBytes().isEmpty()) {
        size += com.google.protobuf.GeneratedMessageV3.computeStringSize(1, id_);
      }
      if (principal_ != null) {
        size += com.google.protobuf.CodedOutputStream
          .computeMessageSize(2, getPrincipal());
      }
      if (loginAt_ != 0L) {
        size += com.google.protobuf.CodedOutputStream
          .computeInt64Size(3, loginAt_);
      }
      if (lastAccessAt_ != 0L) {
        size += com.google.protobuf.CodedOutputStream
          .computeInt64Size(4, lastAccessAt_);
      }
      if (agent_ != null) {
        size += com.google.protobuf.CodedOutputStream
          .computeMessageSize(5, getAgent());
      }
      size += unknownFields.getSerializedSize();
      memoizedSize = size;
      return size;
    }

    @java.lang.Override
    public boolean equals(final java.lang.Object obj) {
      if (obj == this) {
       return true;
      }
      if (!(obj instanceof org.beangle.security.session.protobuf.Model.Session)) {
        return super.equals(obj);
      }
      org.beangle.security.session.protobuf.Model.Session other = (org.beangle.security.session.protobuf.Model.Session) obj;

      boolean result = true;
      result = result && getId()
          .equals(other.getId());
      result = result && (hasPrincipal() == other.hasPrincipal());
      if (hasPrincipal()) {
        result = result && getPrincipal()
            .equals(other.getPrincipal());
      }
      result = result && (getLoginAt()
          == other.getLoginAt());
      result = result && (getLastAccessAt()
          == other.getLastAccessAt());
      result = result && (hasAgent() == other.hasAgent());
      if (hasAgent()) {
        result = result && getAgent()
            .equals(other.getAgent());
      }
      result = result && unknownFields.equals(other.unknownFields);
      return result;
    }

    @java.lang.Override
    public int hashCode() {
      if (memoizedHashCode != 0) {
        return memoizedHashCode;
      }
      int hash = 41;
      hash = (19 * hash) + getDescriptor().hashCode();
      hash = (37 * hash) + ID_FIELD_NUMBER;
      hash = (53 * hash) + getId().hashCode();
      if (hasPrincipal()) {
        hash = (37 * hash) + PRINCIPAL_FIELD_NUMBER;
        hash = (53 * hash) + getPrincipal().hashCode();
      }
      hash = (37 * hash) + LOGINAT_FIELD_NUMBER;
      hash = (53 * hash) + com.google.protobuf.Internal.hashLong(
          getLoginAt());
      hash = (37 * hash) + LASTACCESSAT_FIELD_NUMBER;
      hash = (53 * hash) + com.google.protobuf.Internal.hashLong(
          getLastAccessAt());
      if (hasAgent()) {
        hash = (37 * hash) + AGENT_FIELD_NUMBER;
        hash = (53 * hash) + getAgent().hashCode();
      }
      hash = (29 * hash) + unknownFields.hashCode();
      memoizedHashCode = hash;
      return hash;
    }

    public static org.beangle.security.session.protobuf.Model.Session parseFrom(
        java.nio.ByteBuffer data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static org.beangle.security.session.protobuf.Model.Session parseFrom(
        java.nio.ByteBuffer data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static org.beangle.security.session.protobuf.Model.Session parseFrom(
        com.google.protobuf.ByteString data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static org.beangle.security.session.protobuf.Model.Session parseFrom(
        com.google.protobuf.ByteString data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static org.beangle.security.session.protobuf.Model.Session parseFrom(byte[] data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data);
    }
    public static org.beangle.security.session.protobuf.Model.Session parseFrom(
        byte[] data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return PARSER.parseFrom(data, extensionRegistry);
    }
    public static org.beangle.security.session.protobuf.Model.Session parseFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static org.beangle.security.session.protobuf.Model.Session parseFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }
    public static org.beangle.security.session.protobuf.Model.Session parseDelimitedFrom(java.io.InputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input);
    }
    public static org.beangle.security.session.protobuf.Model.Session parseDelimitedFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
    }
    public static org.beangle.security.session.protobuf.Model.Session parseFrom(
        com.google.protobuf.CodedInputStream input)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input);
    }
    public static org.beangle.security.session.protobuf.Model.Session parseFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return com.google.protobuf.GeneratedMessageV3
          .parseWithIOException(PARSER, input, extensionRegistry);
    }

    public Builder newBuilderForType() { return newBuilder(); }
    public static Builder newBuilder() {
      return DEFAULT_INSTANCE.toBuilder();
    }
    public static Builder newBuilder(org.beangle.security.session.protobuf.Model.Session prototype) {
      return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
    }
    public Builder toBuilder() {
      return this == DEFAULT_INSTANCE
          ? new Builder() : new Builder().mergeFrom(this);
    }

    @java.lang.Override
    protected Builder newBuilderForType(
        com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
      Builder builder = new Builder(parent);
      return builder;
    }
    /**
     * Protobuf type {@code Session}
     */
    public static final class Builder extends
        com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
        // @@protoc_insertion_point(builder_implements:Session)
        org.beangle.security.session.protobuf.Model.SessionOrBuilder {
      public static final com.google.protobuf.Descriptors.Descriptor
          getDescriptor() {
        return org.beangle.security.session.protobuf.Model.internal_static_Session_descriptor;
      }

      protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
          internalGetFieldAccessorTable() {
        return org.beangle.security.session.protobuf.Model.internal_static_Session_fieldAccessorTable
            .ensureFieldAccessorsInitialized(
                org.beangle.security.session.protobuf.Model.Session.class, org.beangle.security.session.protobuf.Model.Session.Builder.class);
      }

      // Construct using org.beangle.security.session.protobuf.Model.Session.newBuilder()
      private Builder() {
        maybeForceBuilderInitialization();
      }

      private Builder(
          com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
        super(parent);
        maybeForceBuilderInitialization();
      }
      private void maybeForceBuilderInitialization() {
        if (com.google.protobuf.GeneratedMessageV3
                .alwaysUseFieldBuilders) {
        }
      }
      public Builder clear() {
        super.clear();
        id_ = "";

        if (principalBuilder_ == null) {
          principal_ = null;
        } else {
          principal_ = null;
          principalBuilder_ = null;
        }
        loginAt_ = 0L;

        lastAccessAt_ = 0L;

        if (agentBuilder_ == null) {
          agent_ = null;
        } else {
          agent_ = null;
          agentBuilder_ = null;
        }
        return this;
      }

      public com.google.protobuf.Descriptors.Descriptor
          getDescriptorForType() {
        return org.beangle.security.session.protobuf.Model.internal_static_Session_descriptor;
      }

      public org.beangle.security.session.protobuf.Model.Session getDefaultInstanceForType() {
        return org.beangle.security.session.protobuf.Model.Session.getDefaultInstance();
      }

      public org.beangle.security.session.protobuf.Model.Session build() {
        org.beangle.security.session.protobuf.Model.Session result = buildPartial();
        if (!result.isInitialized()) {
          throw newUninitializedMessageException(result);
        }
        return result;
      }

      public org.beangle.security.session.protobuf.Model.Session buildPartial() {
        org.beangle.security.session.protobuf.Model.Session result = new org.beangle.security.session.protobuf.Model.Session(this);
        result.id_ = id_;
        if (principalBuilder_ == null) {
          result.principal_ = principal_;
        } else {
          result.principal_ = principalBuilder_.build();
        }
        result.loginAt_ = loginAt_;
        result.lastAccessAt_ = lastAccessAt_;
        if (agentBuilder_ == null) {
          result.agent_ = agent_;
        } else {
          result.agent_ = agentBuilder_.build();
        }
        onBuilt();
        return result;
      }

      public Builder clone() {
        return (Builder) super.clone();
      }
      public Builder setField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          java.lang.Object value) {
        return (Builder) super.setField(field, value);
      }
      public Builder clearField(
          com.google.protobuf.Descriptors.FieldDescriptor field) {
        return (Builder) super.clearField(field);
      }
      public Builder clearOneof(
          com.google.protobuf.Descriptors.OneofDescriptor oneof) {
        return (Builder) super.clearOneof(oneof);
      }
      public Builder setRepeatedField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          int index, java.lang.Object value) {
        return (Builder) super.setRepeatedField(field, index, value);
      }
      public Builder addRepeatedField(
          com.google.protobuf.Descriptors.FieldDescriptor field,
          java.lang.Object value) {
        return (Builder) super.addRepeatedField(field, value);
      }
      public Builder mergeFrom(com.google.protobuf.Message other) {
        if (other instanceof org.beangle.security.session.protobuf.Model.Session) {
          return mergeFrom((org.beangle.security.session.protobuf.Model.Session)other);
        } else {
          super.mergeFrom(other);
          return this;
        }
      }

      public Builder mergeFrom(org.beangle.security.session.protobuf.Model.Session other) {
        if (other == org.beangle.security.session.protobuf.Model.Session.getDefaultInstance()) return this;
        if (!other.getId().isEmpty()) {
          id_ = other.id_;
          onChanged();
        }
        if (other.hasPrincipal()) {
          mergePrincipal(other.getPrincipal());
        }
        if (other.getLoginAt() != 0L) {
          setLoginAt(other.getLoginAt());
        }
        if (other.getLastAccessAt() != 0L) {
          setLastAccessAt(other.getLastAccessAt());
        }
        if (other.hasAgent()) {
          mergeAgent(other.getAgent());
        }
        this.mergeUnknownFields(other.unknownFields);
        onChanged();
        return this;
      }

      public final boolean isInitialized() {
        return true;
      }

      public Builder mergeFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws java.io.IOException {
        org.beangle.security.session.protobuf.Model.Session parsedMessage = null;
        try {
          parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
        } catch (com.google.protobuf.InvalidProtocolBufferException e) {
          parsedMessage = (org.beangle.security.session.protobuf.Model.Session) e.getUnfinishedMessage();
          throw e.unwrapIOException();
        } finally {
          if (parsedMessage != null) {
            mergeFrom(parsedMessage);
          }
        }
        return this;
      }

      private java.lang.Object id_ = "";
      /**
       * <code>string id = 1;</code>
       */
      public java.lang.String getId() {
        java.lang.Object ref = id_;
        if (!(ref instanceof java.lang.String)) {
          com.google.protobuf.ByteString bs =
              (com.google.protobuf.ByteString) ref;
          java.lang.String s = bs.toStringUtf8();
          id_ = s;
          return s;
        } else {
          return (java.lang.String) ref;
        }
      }
      /**
       * <code>string id = 1;</code>
       */
      public com.google.protobuf.ByteString
          getIdBytes() {
        java.lang.Object ref = id_;
        if (ref instanceof String) {
          com.google.protobuf.ByteString b =
              com.google.protobuf.ByteString.copyFromUtf8(
                  (java.lang.String) ref);
          id_ = b;
          return b;
        } else {
          return (com.google.protobuf.ByteString) ref;
        }
      }
      /**
       * <code>string id = 1;</code>
       */
      public Builder setId(
          java.lang.String value) {
        if (value == null) {
    throw new NullPointerException();
  }

        id_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>string id = 1;</code>
       */
      public Builder clearId() {

        id_ = getDefaultInstance().getId();
        onChanged();
        return this;
      }
      /**
       * <code>string id = 1;</code>
       */
      public Builder setIdBytes(
          com.google.protobuf.ByteString value) {
        if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);

        id_ = value;
        onChanged();
        return this;
      }

      private org.beangle.security.session.protobuf.Model.Account principal_ = null;
      private com.google.protobuf.SingleFieldBuilderV3<
          org.beangle.security.session.protobuf.Model.Account, org.beangle.security.session.protobuf.Model.Account.Builder, org.beangle.security.session.protobuf.Model.AccountOrBuilder> principalBuilder_;
      /**
       * <code>.Account principal = 2;</code>
       */
      public boolean hasPrincipal() {
        return principalBuilder_ != null || principal_ != null;
      }
      /**
       * <code>.Account principal = 2;</code>
       */
      public org.beangle.security.session.protobuf.Model.Account getPrincipal() {
        if (principalBuilder_ == null) {
          return principal_ == null ? org.beangle.security.session.protobuf.Model.Account.getDefaultInstance() : principal_;
        } else {
          return principalBuilder_.getMessage();
        }
      }
      /**
       * <code>.Account principal = 2;</code>
       */
      public Builder setPrincipal(org.beangle.security.session.protobuf.Model.Account value) {
        if (principalBuilder_ == null) {
          if (value == null) {
            throw new NullPointerException();
          }
          principal_ = value;
          onChanged();
        } else {
          principalBuilder_.setMessage(value);
        }

        return this;
      }
      /**
       * <code>.Account principal = 2;</code>
       */
      public Builder setPrincipal(
          org.beangle.security.session.protobuf.Model.Account.Builder builderForValue) {
        if (principalBuilder_ == null) {
          principal_ = builderForValue.build();
          onChanged();
        } else {
          principalBuilder_.setMessage(builderForValue.build());
        }

        return this;
      }
      /**
       * <code>.Account principal = 2;</code>
       */
      public Builder mergePrincipal(org.beangle.security.session.protobuf.Model.Account value) {
        if (principalBuilder_ == null) {
          if (principal_ != null) {
            principal_ =
              org.beangle.security.session.protobuf.Model.Account.newBuilder(principal_).mergeFrom(value).buildPartial();
          } else {
            principal_ = value;
          }
          onChanged();
        } else {
          principalBuilder_.mergeFrom(value);
        }

        return this;
      }
      /**
       * <code>.Account principal = 2;</code>
       */
      public Builder clearPrincipal() {
        if (principalBuilder_ == null) {
          principal_ = null;
          onChanged();
        } else {
          principal_ = null;
          principalBuilder_ = null;
        }

        return this;
      }
      /**
       * <code>.Account principal = 2;</code>
       */
      public org.beangle.security.session.protobuf.Model.Account.Builder getPrincipalBuilder() {

        onChanged();
        return getPrincipalFieldBuilder().getBuilder();
      }
      /**
       * <code>.Account principal = 2;</code>
       */
      public org.beangle.security.session.protobuf.Model.AccountOrBuilder getPrincipalOrBuilder() {
        if (principalBuilder_ != null) {
          return principalBuilder_.getMessageOrBuilder();
        } else {
          return principal_ == null ?
              org.beangle.security.session.protobuf.Model.Account.getDefaultInstance() : principal_;
        }
      }
      /**
       * <code>.Account principal = 2;</code>
       */
      private com.google.protobuf.SingleFieldBuilderV3<
          org.beangle.security.session.protobuf.Model.Account, org.beangle.security.session.protobuf.Model.Account.Builder, org.beangle.security.session.protobuf.Model.AccountOrBuilder>
          getPrincipalFieldBuilder() {
        if (principalBuilder_ == null) {
          principalBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
              org.beangle.security.session.protobuf.Model.Account, org.beangle.security.session.protobuf.Model.Account.Builder, org.beangle.security.session.protobuf.Model.AccountOrBuilder>(
                  getPrincipal(),
                  getParentForChildren(),
                  isClean());
          principal_ = null;
        }
        return principalBuilder_;
      }

      private long loginAt_ ;
      /**
       * <code>int64 loginAt = 3;</code>
       */
      public long getLoginAt() {
        return loginAt_;
      }
      /**
       * <code>int64 loginAt = 3;</code>
       */
      public Builder setLoginAt(long value) {

        loginAt_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>int64 loginAt = 3;</code>
       */
      public Builder clearLoginAt() {

        loginAt_ = 0L;
        onChanged();
        return this;
      }

      private long lastAccessAt_ ;
      /**
       * <code>int64 lastAccessAt = 4;</code>
       */
      public long getLastAccessAt() {
        return lastAccessAt_;
      }
      /**
       * <code>int64 lastAccessAt = 4;</code>
       */
      public Builder setLastAccessAt(long value) {

        lastAccessAt_ = value;
        onChanged();
        return this;
      }
      /**
       * <code>int64 lastAccessAt = 4;</code>
       */
      public Builder clearLastAccessAt() {

        lastAccessAt_ = 0L;
        onChanged();
        return this;
      }

      private org.beangle.security.session.protobuf.Model.Agent agent_ = null;
      private com.google.protobuf.SingleFieldBuilderV3<
          org.beangle.security.session.protobuf.Model.Agent, org.beangle.security.session.protobuf.Model.Agent.Builder, org.beangle.security.session.protobuf.Model.AgentOrBuilder> agentBuilder_;
      /**
       * <code>.Agent agent = 5;</code>
       */
      public boolean hasAgent() {
        return agentBuilder_ != null || agent_ != null;
      }
      /**
       * <code>.Agent agent = 5;</code>
       */
      public org.beangle.security.session.protobuf.Model.Agent getAgent() {
        if (agentBuilder_ == null) {
          return agent_ == null ? org.beangle.security.session.protobuf.Model.Agent.getDefaultInstance() : agent_;
        } else {
          return agentBuilder_.getMessage();
        }
      }
      /**
       * <code>.Agent agent = 5;</code>
       */
      public Builder setAgent(org.beangle.security.session.protobuf.Model.Agent value) {
        if (agentBuilder_ == null) {
          if (value == null) {
            throw new NullPointerException();
          }
          agent_ = value;
          onChanged();
        } else {
          agentBuilder_.setMessage(value);
        }

        return this;
      }
      /**
       * <code>.Agent agent = 5;</code>
       */
      public Builder setAgent(
          org.beangle.security.session.protobuf.Model.Agent.Builder builderForValue) {
        if (agentBuilder_ == null) {
          agent_ = builderForValue.build();
          onChanged();
        } else {
          agentBuilder_.setMessage(builderForValue.build());
        }

        return this;
      }
      /**
       * <code>.Agent agent = 5;</code>
       */
      public Builder mergeAgent(org.beangle.security.session.protobuf.Model.Agent value) {
        if (agentBuilder_ == null) {
          if (agent_ != null) {
            agent_ =
              org.beangle.security.session.protobuf.Model.Agent.newBuilder(agent_).mergeFrom(value).buildPartial();
          } else {
            agent_ = value;
          }
          onChanged();
        } else {
          agentBuilder_.mergeFrom(value);
        }

        return this;
      }
      /**
       * <code>.Agent agent = 5;</code>
       */
      public Builder clearAgent() {
        if (agentBuilder_ == null) {
          agent_ = null;
          onChanged();
        } else {
          agent_ = null;
          agentBuilder_ = null;
        }

        return this;
      }
      /**
       * <code>.Agent agent = 5;</code>
       */
      public org.beangle.security.session.protobuf.Model.Agent.Builder getAgentBuilder() {

        onChanged();
        return getAgentFieldBuilder().getBuilder();
      }
      /**
       * <code>.Agent agent = 5;</code>
       */
      public org.beangle.security.session.protobuf.Model.AgentOrBuilder getAgentOrBuilder() {
        if (agentBuilder_ != null) {
          return agentBuilder_.getMessageOrBuilder();
        } else {
          return agent_ == null ?
              org.beangle.security.session.protobuf.Model.Agent.getDefaultInstance() : agent_;
        }
      }
      /**
       * <code>.Agent agent = 5;</code>
       */
      private com.google.protobuf.SingleFieldBuilderV3<
          org.beangle.security.session.protobuf.Model.Agent, org.beangle.security.session.protobuf.Model.Agent.Builder, org.beangle.security.session.protobuf.Model.AgentOrBuilder>
          getAgentFieldBuilder() {
        if (agentBuilder_ == null) {
          agentBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
              org.beangle.security.session.protobuf.Model.Agent, org.beangle.security.session.protobuf.Model.Agent.Builder, org.beangle.security.session.protobuf.Model.AgentOrBuilder>(
                  getAgent(),
                  getParentForChildren(),
                  isClean());
          agent_ = null;
        }
        return agentBuilder_;
      }
      public final Builder setUnknownFields(
          final com.google.protobuf.UnknownFieldSet unknownFields) {
        return super.setUnknownFieldsProto3(unknownFields);
      }

      public final Builder mergeUnknownFields(
          final com.google.protobuf.UnknownFieldSet unknownFields) {
        return super.mergeUnknownFields(unknownFields);
      }

      // @@protoc_insertion_point(builder_scope:Session)
    }

    // @@protoc_insertion_point(class_scope:Session)
    private static final org.beangle.security.session.protobuf.Model.Session DEFAULT_INSTANCE;
    static {
      DEFAULT_INSTANCE = new org.beangle.security.session.protobuf.Model.Session();
    }

    public static org.beangle.security.session.protobuf.Model.Session getDefaultInstance() {
      return DEFAULT_INSTANCE;
    }

    private static final com.google.protobuf.Parser<Session>
        PARSER = new com.google.protobuf.AbstractParser<Session>() {
      public Session parsePartialFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws com.google.protobuf.InvalidProtocolBufferException {
        return new Session(input, extensionRegistry);
      }
    };

    public static com.google.protobuf.Parser<Session> parser() {
      return PARSER;
    }

    @java.lang.Override
    public com.google.protobuf.Parser<Session> getParserForType() {
      return PARSER;
    }

    public org.beangle.security.session.protobuf.Model.Session getDefaultInstanceForType() {
      return DEFAULT_INSTANCE;
    }

  }

  private static final com.google.protobuf.Descriptors.Descriptor
    internal_static_Account_descriptor;
  private static final
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_Account_fieldAccessorTable;
  private static final com.google.protobuf.Descriptors.Descriptor
    internal_static_Account_DetailsEntry_descriptor;
  private static final
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_Account_DetailsEntry_fieldAccessorTable;
  private static final com.google.protobuf.Descriptors.Descriptor
    internal_static_Agent_descriptor;
  private static final
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_Agent_fieldAccessorTable;
  private static final com.google.protobuf.Descriptors.Descriptor
    internal_static_Session_descriptor;
  private static final
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_Session_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n@main/resources/org/beangle/security/se" +
      "ssion/protobuf/model.proto\"\323\001\n\007Account\022\014" +
      "\n\004name\030\001 \001(\t\022\023\n\013description\030\002 \001(\t\022\023\n\013rem" +
      "oteToken\030\003 \001(\t\022\016\n\006status\030\004 \001(\005\022\023\n\013author" +
      "ities\030\005 \001(\t\022\023\n\013permissions\030\006 \001(\t\022&\n\007deta" +
      "ils\030\007 \003(\0132\025.Account.DetailsEntry\032.\n\014Deta" +
      "ilsEntry\022\013\n\003key\030\001 \001(\t\022\r\n\005value\030\002 \001(\t:\0028\001" +
      "\"-\n\005Agent\022\014\n\004name\030\001 \001(\t\022\n\n\002ip\030\002 \001(\t\022\n\n\002o" +
      "s\030\003 \001(\t\"p\n\007Session\022\n\n\002id\030\001 \001(\t\022\033\n\tprinci" +
      "pal\030\002 \001(\0132\010.Account\022\017\n\007loginAt\030\003 \001(\003\022\024\n\014" +
      "lastAccessAt\030\004 \001(\003\022\025\n\005agent\030\005 \001(\0132\006.Agen" +
      "tB.\n%org.beangle.security.session.protob" +
      "ufB\005Modelb\006proto3"
    };
    com.google.protobuf.Descriptors.FileDescriptor.InternalDescriptorAssigner assigner =
        new com.google.protobuf.Descriptors.FileDescriptor.    InternalDescriptorAssigner() {
          public com.google.protobuf.ExtensionRegistry assignDescriptors(
              com.google.protobuf.Descriptors.FileDescriptor root) {
            descriptor = root;
            return null;
          }
        };
    com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
        }, assigner);
    internal_static_Account_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_Account_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_Account_descriptor,
        new java.lang.String[] { "Name", "Description", "RemoteToken", "Status", "Authorities", "Permissions", "Details", });
    internal_static_Account_DetailsEntry_descriptor =
      internal_static_Account_descriptor.getNestedTypes().get(0);
    internal_static_Account_DetailsEntry_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_Account_DetailsEntry_descriptor,
        new java.lang.String[] { "Key", "Value", });
    internal_static_Agent_descriptor =
      getDescriptor().getMessageTypes().get(1);
    internal_static_Agent_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_Agent_descriptor,
        new java.lang.String[] { "Name", "Ip", "Os", });
    internal_static_Session_descriptor =
      getDescriptor().getMessageTypes().get(2);
    internal_static_Session_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_Session_descriptor,
        new java.lang.String[] { "Id", "Principal", "LoginAt", "LastAccessAt", "Agent", });
  }

  // @@protoc_insertion_point(outer_class_scope)
}
