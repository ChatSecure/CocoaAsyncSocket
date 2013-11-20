//
//  GCDAsyncProxySocket.m
//  OnionKit
//
//  Created by Christopher Ballinger on 11/19/13.
//  Copyright (c) 2013 ChatSecure. All rights reserved.
//

#import "GCDAsyncProxySocket.h"

typedef NS_ENUM(long, GCDAsyncProxySocketTag) {
    kAuthenticationWriteTag = 0,
    kAuthenticationReadTag
};

static const uint8_t kPlainAuthBytes[] = {'\x05','\x02','\x00','\x02'};
static const NSUInteger kPlainAuthBytesLength = 4;
static const uint8_t kNoAuthBytes[] = {'\x05','\x01','\x00'};
static const NSUInteger kNoAuthBytesLength = 3;

@interface GCDAsyncProxySocket()
@property (nonatomic, strong, readonly) GCDAsyncSocket *proxySocket;
@property (nonatomic, readonly) dispatch_queue_t proxyDelegateQueue;
@property (nonatomic, strong, readonly) NSString *destinationHost;
@property (nonatomic, readonly) uint16_t destinationPort;
@end

@implementation GCDAsyncProxySocket

- (void) setProxyHost:(NSString *)host port:(uint16_t)port version:(GCDAsyncSocketSOCKSVersion)version {
    _proxyHost = host;
    _proxyPort = port;
    _proxyVersion = version;
}

- (void) setProxyUsername:(NSString *)username password:(NSString *)password {
    _proxyUsername = username;
    _proxyPassword = password;
}

- (id)initWithDelegate:(id)aDelegate delegateQueue:(dispatch_queue_t)dq socketQueue:(dispatch_queue_t)sq {
    if (self = [super initWithDelegate:aDelegate delegateQueue:dq socketQueue:sq]) {
        _proxyHost = nil;
        _proxyPort = 0;
        _proxyVersion = -1;
        _destinationHost = nil;
        _destinationPort = 0;
        _proxyUsername = nil;
        _proxyPassword = nil;
        _proxyDelegateQueue = dispatch_queue_create("GCDAsyncProxySocket delegate queue", 0);
    }
    return self;
}

- (BOOL)connectToHost:(NSString *)inHost
               onPort:(uint16_t)port
         viaInterface:(NSString *)inInterface
          withTimeout:(NSTimeInterval)timeout
                error:(NSError **)errPtr
{
    if (!self.proxySocket) {
        _proxySocket = [[GCDAsyncSocket alloc] initWithDelegate:self delegateQueue:self.proxyDelegateQueue socketQueue:NULL];
    }
    _destinationHost = inHost;
    _destinationPort = port;
    return [self.proxySocket connectToHost:self.proxyHost onPort:self.proxyPort viaInterface:inInterface withTimeout:timeout error:errPtr];
}

- (void) socket:(GCDAsyncSocket *)sock didConnectToHost:(NSString *)host port:(uint16_t)port {
    NSLog(@"proxySocket connected to proxy %@:%d / destination %@:%d", host, port, self.destinationHost, self.self.destinationPort);
    
    NSData *authData = nil;
    if (self.proxyUsername.length) {
        authData = [NSData dataWithBytes:&kPlainAuthBytes length:kPlainAuthBytesLength];
    } else {
        authData = [NSData dataWithBytes:&kNoAuthBytes length:kNoAuthBytesLength];
    }
    
    [self.proxySocket writeData:authData withTimeout:-1 tag:kAuthenticationWriteTag];
    /*
    if (self.delegate && [self.delegate respondsToSelector:@selector(socket:didConnectToHost:port:)]) {
        dispatch_async(self.delegateQueue, ^{
            @autoreleasepool {
                [self.delegate socket:self didConnectToHost:self.destinationHost port:self.destinationPort];
            }
        });
    }*/
}

- (void) socket:(GCDAsyncSocket *)sock didWriteDataWithTag:(long)tag {
    if (tag == kAuthenticationWriteTag) {
        [sock readDataToLength:2 withTimeout:-1 tag:kAuthenticationReadTag];
    }
}

- (void) socket:(GCDAsyncSocket *)sock didReadData:(NSData *)data withTag:(long)tag {
    if (tag == kAuthenticationReadTag) {
        NSAssert(data.length != 2, @"data.length must be 2");
        uint8_t *bytes = (uint8_t*)[data bytes];
        if (bytes[0] != '\x05') {
            NSLog(@"Error setting up authentication");
            [sock disconnect];
            NSError *error = [NSError errorWithDomain:GCDAsyncSocketErrorDomain code:GCDAsyncProxySocketAuthenticationError userInfo:@{NSLocalizedDescriptionKey: @"Authentication Error"}];
            [self socketDidDisconnect:self withError:error];
            return;
        }
        uint8_t authValue = bytes[1];
        if (authValue == '\x00') { // No authentication required
            
        } else if (authValue == '\x02') { // Password auth required
            
        }
    }
}

- (void)socketDidDisconnect:(GCDAsyncSocket *)sock withError:(NSError *)err {
    NSLog(@"proxySocket disconnected from proxy %@:%d / destination %@:%d", self.proxyHost, self.proxyPort, self.destinationHost, self.self.destinationPort);

    if (self.delegate && [self.delegate respondsToSelector:@selector(socket:didConnectToHost:port:)]) {
        dispatch_async(self.delegateQueue, ^{
            @autoreleasepool {
                [self.delegate socketDidDisconnect:self withError:err];
            }
        });
    }}


@end
