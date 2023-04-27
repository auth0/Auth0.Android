# Gson

-keepattributes Signature
-keepattributes *Annotation*

-dontwarn com.google.gson.internal.UnsafeAllocator

#R8
# - See https://r8.googlesource.com/r8/+/refs/heads/master/compatibility-faq.md
# - See https://medium.com/@harryaung/mysterious-null-crash-with-gson-serializedname-fields-when-r8-proguard-is-on-f8a4bd036e34
-if class *
-keepclasseswithmembers class <1> {
  <init>(...);
  @com.google.gson.annotations.SerializedName <fields>;
}
-keep,allowobfuscation @interface com.google.gson.annotations.SerializedName
-keep class com.google.gson.reflect.TypeToken { *; }
-keep class * extends com.google.gson.reflect.TypeToken