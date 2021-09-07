/*
 * ThatWebInspector
 *
 * Created by EvilPenguin
 */

#include <Foundation/Foundation.h>
#include <Security/Security.h>
#include <dlfcn.h>
#include <substrate.h>
#include <syslog.h>

#ifdef DEBUG
    #define DLog(FORMAT, ...) syslog(LOG_ERR, "+[XPCSniffer] %s\n", [[NSString stringWithFormat:FORMAT, ##__VA_ARGS__] UTF8String]);
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
    DLog(@"Signing Identifier: %@", (__bridge NSString *)_SecTaskCopySigningIdentifier(task, NULL));
    DLog(@"Value for entitlement: %@", (__bridge NSString *)entitlement);

    if (CFArrayContainsValue(_web_entitlements, CFRangeMake(0, CFArrayGetCount(_web_entitlements)), entitlement)) {
        return kCFBooleanTrue;
    }

    return original_SecTaskCopyValueForEntitlement(task, entitlement, error);
}

#pragma mark - Constructor

%ctor {
	@autoreleasepool {
        DLog(@"Running");

        // Setup globals
        _web_entitlements = _needed_entitlements();
        DLog(@"Entitlements size: %li (%p)", CFArrayGetCount(_web_entitlements), _web_entitlements);

        // Load Security
        MSImageRef security_handle = MSGetImageByName("/System/Library/Frameworks/Security.framework/Security");
        DLog(@"Security: %p", security_handle);

        if (security_handle) {
            // _SecTaskCopySigningIdentifier
            _SecTaskCopySigningIdentifier = (_SecTaskCopySigningIdentifierType *)MSFindSymbol(security_handle, "_SecTaskCopySigningIdentifier");
            DLog(@"_SecTaskCopySigningIdentifier: %p", _SecTaskCopySigningIdentifier);

            // _SecTaskCopyValueForEntitlement
            void *_SecTaskCopyValueForEntitlement = MSFindSymbol(security_handle, "_SecTaskCopyValueForEntitlement");
            DLog(@"_SecTaskCopyValueForEntitlement: %p", _SecTaskCopyValueForEntitlement);

            if (_SecTaskCopyValueForEntitlement) {
                MSHookFunction(_SecTaskCopyValueForEntitlement, (void *)replaced_SecTaskCopyValueForEntitlement, (void **)&original_SecTaskCopyValueForEntitlement);
            }
        }
    }
}
