//
//  GCDAsyncWrapperSocket.m
//  OnionKit
//
//  Created by Christopher Ballinger on 11/21/13.
//  Copyright (c) 2013 ChatSecure. All rights reserved.
//

typedef NS_ENUM(long, GCDAsyncWrapperSocketTag) {
    kDataWriteTag = 0,
    kDataReadTag
};

#import "GCDAsyncWrapperSocket.h"

@interface GCDAsyncWrapperSocket()
@property (nonatomic, strong, readonly) GCDAsyncSocket *wrapperSocket;
@property (nonatomic, readonly) dispatch_queue_t wrapperDelegateQueue;
@end

@implementation GCDAsyncWrapperSocket

- (id)initWithDelegate:(id)aDelegate delegateQueue:(dispatch_queue_t)dq socketQueue:(dispatch_queue_t)sq {
    if (self = [super initWithDelegate:aDelegate delegateQueue:dq socketQueue:sq]) {
        _wrapperDelegateQueue = dispatch_queue_create("GCDAsyncProxySocket delegate queue", 0);
    }
    return self;
}

- (BOOL)connectToHost:(NSString *)inHost
               onPort:(uint16_t)port
         viaInterface:(NSString *)inInterface
          withTimeout:(NSTimeInterval)timeout
                error:(NSError **)errPtr
{
    if (!self.wrapperSocket) {
        _wrapperSocket = [[GCDAsyncSocket alloc] initWithDelegate:self delegateQueue:self.wrapperDelegateQueue socketQueue:NULL];
    }
    return [self.wrapperSocket connectToHost:inHost onPort:port viaInterface:inInterface withTimeout:timeout error:errPtr];
}

- (void) writeData:(NSData *)data withTimeout:(NSTimeInterval)timeout tag:(long)tag {
    [self.wrapperSocket writeData:data withTimeout:-1 tag:kDataWriteTag];
}

- (void) startTLS:(NSDictionary *)tlsSettings {
    [self.wrapperSocket startTLS:tlsSettings];
}

#pragma mark GCDAsyncSocketDelegate methods

- (void) socket:(GCDAsyncSocket *)sock didConnectToHost:(NSString *)host port:(uint16_t)port {
    if (self.delegate && [self.delegate respondsToSelector:@selector(socket:didConnectToHost:port:)]) {
        dispatch_async(self.delegateQueue, ^{
            @autoreleasepool {
                [self.delegate socket:self didConnectToHost:host port:port];
            }
        });
    }
}

- (void) socket:(GCDAsyncSocket *)sock didWriteDataWithTag:(long)tag {
    if (tag == kDataWriteTag) {
        NSLog(@"didWrite kDataWriteTag");
        [sock readDataWithTimeout:-1 tag:kDataReadTag];
    }
}

- (void) socket:(GCDAsyncSocket *)sock didReadData:(NSData *)data withTag:(long)tag {
    if (tag == kDataReadTag) {
        [sock readDataWithTimeout:-1 tag:kDataReadTag];
        NSLog(@"didRead kDataReadTag: %@", data.description);
        if (self.delegate && [self.delegate respondsToSelector:@selector(socket:didReadData:withTag:)]) {
            dispatch_async(self.delegateQueue, ^{
                @autoreleasepool {
                    [self.delegate socket:self didReadData:data withTag:-1];
                }
            });
        }
    }
}

- (void)socketDidDisconnect:(GCDAsyncSocket *)sock withError:(NSError *)err {
    if (self.delegate && [self.delegate respondsToSelector:@selector(socketDidDisconnect:withError:)]) {
        dispatch_async(self.delegateQueue, ^{
            @autoreleasepool {
                [self.delegate socketDidDisconnect:self withError:err];
            }
        });
    }
}

- (void) socketDidSecure:(GCDAsyncSocket *)sock {
    //NSLog(@"didSecure proxy %@:%d / destination %@:%d", self.proxyHost, self.proxyPort, self.destinationHost, self.self.destinationPort);
    
    if (self.delegate && [self.delegate respondsToSelector:@selector(socketDidSecure:)]) {
        dispatch_async(self.delegateQueue, ^{
            @autoreleasepool {
                [self.delegate socketDidSecure:self];
            }
        });
    }
}

@end
