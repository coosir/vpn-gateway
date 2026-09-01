//go:build desktop && darwin

package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

static void setDockVisible(bool visible) {
    void (^block)(void) = ^{
        NSApplicationActivationPolicy policy = visible ? NSApplicationActivationPolicyRegular : NSApplicationActivationPolicyAccessory;
        if ([NSApp activationPolicy] != policy) {
            [NSApp setActivationPolicy:policy];
        }
        if (visible) {
            [NSApp activateIgnoringOtherApps:YES];
        }
    };
    if ([NSThread isMainThread]) {
        block();
    } else {
        dispatch_async(dispatch_get_main_queue(), block);
    }
}
*/
import "C"

func showDockIcon() {
	C.setDockVisible(true)
}

func hideDockIcon() {
	C.setDockVisible(false)
}
