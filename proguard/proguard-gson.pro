# Gson

-keepattributes Signature
-keepattributes *Annotation*

-dontwarn com.google.gson.internal.UnsafeAllocator

#R8
# - See https://r8.googlesource.com/r8/+/refs/heads/master/compatibility-faq.md
# - See https://medium.com/@harryaung/mysterious-null-crash-with-gson-serializedname-fields-when-r8-proguard-is-on-f8a4bd036e34
-keepclassmembers,allowobfuscation class * {
  @com.google.gson.annotations.SerializedName <fields>;
}
-keep,allowobfuscation @interface com.google.gson.annotations.SerializedName