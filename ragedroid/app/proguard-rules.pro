-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}
-keep class ragewarden.ragedroid.jni.RageNative { *; }
-keep class ragewarden.ragedroid.jni.RageNativeException { *; }
-keep class ragewarden.ragedroid.jni.RageNativeException$* { <init>(...); }
-keep interface ragewarden.ragedroid.identities.KotlinIdentity { *; }
-keepclassmembers class * implements ragewarden.ragedroid.identities.KotlinIdentity {
    byte[] tryUnwrapBlocking(java.lang.String, java.lang.String[], byte[]);
}

-keep class androidx.profileinstaller.** { *; }
-dontwarn androidx.benchmark.**
-dontwarn com.google.errorprone.annotations.**
-dontwarn com.google.j2objc.annotations.**
-dontwarn org.checkerframework.**
-dontwarn javax.lang.model.element.Modifier
