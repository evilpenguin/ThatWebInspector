/*
 * ThatWebInspector
 *
 * Created by EvilPenguin
 */

#include <Foundation/Foundation.h>
#include <Security/Security.h>
#include <dlfcn.h>
#include <substrate.h>

#ifdef DEBUG
    #define DLog(FORMAT, ...) fprintf(stderr, "+[ThatWebInspector] %s\n", [[NSString stringWithFormat:FORMAT, ##__VA_ARGS__] UTF8String]);
#else 
    #define DLog(...) (void)0
#endif

#pragma mark - Entitlements

static CFArrayRef _web_entitlements = nil;
static CFArrayRef _needed_entitlements(void) {
    static dispatch_once_t onceToken;
    static CFArrayRef entitlements = nil;

    dispatch_once (&onceToken, ^{
        CFStringRef values[4] = {
            CFSTR("com.apple.security.get-task-allow"),
            CFSTR("com.apple.webinspector.allow"),
            CFSTR("com.apple.private.webinspector.allow-remote-inspection"),
            CFSTR("com.apple.private.webinspector.allow-carrier-remote-inspection")
        };

        entitlements = CFArrayCreate(NULL, (const void **)values, 4, &kCFTypeArrayCallBacks);
    });

    return entitlements;
}

#pragma mark - SecTaskCopySigningIdentifier

typedef CFStringRef (_SecTaskCopySigningIdentifierType)(void *task, CFErrorRef _Nullable *error);
static _SecTaskCopySigningIdentifierType *_SecTaskCopySigningIdentifier = nil;

#pragma mark - SecTaskCopyValueForEntitlement

static CFTypeRef (*original_SecTaskCopyValueForEntitlement)(void *task, CFStringRef entitlement, CFErrorRef _Nullable *error);
static CFTypeRef replaced_SecTaskCopyValueForEntitlement(void *task, CFStringRef entitlement, CFErrorRef _Nullable *error) {
	DLog(@"Looking for entitlement: %@", (__bridge NSString *)entitlement);

    CFStringRef signing_identifier = _SecTaskCopySigningIdentifier(task, NULL);
    if (CFArrayContainsValue(_web_entitlements, CFRangeMake(0, CFArrayGetCount(_web_entitlements)), signing_identifier)) {
        return kCFBooleanTrue;
    }

    return original_SecTaskCopyValueForEntitlement(task, entitlement, error);
}

#pragma mark - Constructor

%ctor {
	@autoreleasepool {
        DLog(@"Enabled");

        // Setup globals
        _web_entitlements = _needed_entitlements();
        DLog(@"Entitlements size: %li", CFArrayGetCount(_web_entitlements));

        // Load Security
        void *security_handle = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW);
        DLog(@"Security: %p", security_handle);

        if (security_handle) {
            // _SecTaskCopySigningIdentifier
            _SecTaskCopySigningIdentifier = (_SecTaskCopySigningIdentifierType *)dlsym(security_handle, "_SecTaskCopySigningIdentifier");
            DLog(@"_SecTaskCopySigningIdentifier: %p", _SecTaskCopySigningIdentifier);

            // _SecTaskCopyValueForEntitlement
            void *_SecTaskCopyValueForEntitlement = dlsym(security_handle, "_SecTaskCopyValueForEntitlement");
            DLog(@"_SecTaskCopyValueForEntitlement: %p", _SecTaskCopyValueForEntitlement);

            if (_SecTaskCopyValueForEntitlement) {
                MSHookFunction(_SecTaskCopyValueForEntitlement, (void *)replaced_SecTaskCopyValueForEntitlement, (void **)&original_SecTaskCopyValueForEntitlement);
            }
        }
    }
}
