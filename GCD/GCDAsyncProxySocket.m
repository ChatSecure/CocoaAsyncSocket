//
//  GCDAsyncProxySocket.m
//  OnionKit
//
//  Created by Christopher Ballinger on 11/19/13.
//  Copyright (c) 2013 ChatSecure. All rights reserved.
//

#import "GCDAsyncProxySocket.h"
#import "Endian.h"

typedef NS_ENUM(long, GCDAsyncProxySocketTag) {
    kAuthenticationWriteTag = 0,
    kAuthenticationReadTag,
    kDestinationWriteTag,
    kDestinationReadTag,
    kDataWriteTag,
    kDataReadTag
};

static const uint8_t kPlainAuthBytes[] = {0x05, 0x02, 0x00, 0x02};
static const NSUInteger kPlainAuthBytesLength = 4;
static const uint8_t kNoAuthBytes[] = {0x05, 0x01, 0x00};
static const NSUInteger kNoAuthBytesLength = 3;
static const uint8_t kConnectionPreambleBytes[] = {0x05, 0x01, 0x00};
static const NSUInteger kConnectionPreambleBytesLength = 3;


@interface GCDAsyncProxySocket()
@property (nonatomic, strong, readonly) GCDAsyncSocket *proxySocket;
@property (nonatomic, readonly) dispatch_queue_t proxyDelegateQueue;
@property (nonatomic, strong, readonly) NSString *destinationHost;
@property (nonatomic, strong, readonly) NSData *destinationAddress;
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

#pragma mark Overridden methods

- (id)initWithDelegate:(id)aDelegate delegateQueue:(dispatch_queue_t)dq socketQueue:(dispatch_queue_t)sq {
    if (self = [super initWithDelegate:aDelegate delegateQueue:dq socketQueue:sq]) {
        _proxyHost = nil;
        _proxyPort = 0;
        _proxyVersion = -1;
        _destinationHost = nil;
        _destinationPort = 0;
        _destinationAddress = nil;
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

- (void) writeData:(NSData *)data withTimeout:(NSTimeInterval)timeout tag:(long)tag {
    [self.proxySocket writeData:data withTimeout:-1 tag:kDataWriteTag];
}

- (void) startTLS:(NSDictionary *)tlsSettings {
    NSMutableDictionary *settings = [NSMutableDictionary dictionaryWithDictionary:tlsSettings];
    NSString *peerName = self.destinationHost;
    if (self.destinationAddress) {
        peerName = [GCDAsyncSocket hostFromAddress:self.destinationAddress];
    }
    [settings setObject:peerName forKey:(NSString *)kCFStreamSSLPeerName];
    [self.proxySocket startTLS:settings];
}

//- (OSStatus)sslWriteWithBuffer:(const void *)buffer length:(size_t *)bufferLength
//- (OSStatus)sslReadWithBuffer:(void *)buffer length:(size_t *)bufferLength


#pragma mark GCDAsyncSocketDelegate methods

- (void) socket:(GCDAsyncSocket *)sock didConnectToHost:(NSString *)host port:(uint16_t)port {
    NSLog(@"proxySocket connected to proxy %@:%d / destination %@:%d", host, port, self.destinationHost, self.self.destinationPort);
    
    NSData *authData = nil;
    if (self.proxyUsername.length) {
        authData = [NSData dataWithBytes:&kPlainAuthBytes length:kPlainAuthBytesLength];
    } else {
        authData = [NSData dataWithBytes:&kNoAuthBytes length:kNoAuthBytesLength];
    }
    
    [self.proxySocket writeData:authData withTimeout:-1 tag:kAuthenticationWriteTag];
}

- (void) socket:(GCDAsyncSocket *)sock didWriteDataWithTag:(long)tag {
    if (tag == kAuthenticationWriteTag) {
        NSLog(@"didWrite kAuthenticationWriteTag");
        [sock readDataToLength:2 withTimeout:-1 tag:kAuthenticationReadTag];
    } else if (tag == kDestinationWriteTag) {
        NSLog(@"didWrite kDestinationWriteTag");
        [sock readDataToLength:4 withTimeout:-1 tag:kDestinationReadTag];
    } else if (tag == kDataWriteTag) {
        NSLog(@"didWrite kDataWriteTag");
        [sock readDataWithTimeout:-1 tag:kDataReadTag];
    }
}

- (void) socket:(GCDAsyncSocket *)sock didReadData:(NSData *)data withTag:(long)tag {
    if (tag == kAuthenticationReadTag) {
        NSLog(@"didRead kAuthenticationReadTag: %@", data.description);
        NSAssert(data.length == 2, @"data.length must be 2");
        uint8_t *bytes = (uint8_t*)[data bytes];
        uint8_t firstByte = bytes[0];
        if (firstByte != 0x05) {
            NSLog(@"Error setting up authentication");
            [sock disconnect];
            NSError *error = [NSError errorWithDomain:GCDAsyncSocketErrorDomain code:GCDAsyncProxySocketAuthenticationError userInfo:@{NSLocalizedDescriptionKey: @"Authentication Error"}];
            [self socketDidDisconnect:self withError:error];
            return;
        }
        uint8_t authValue = bytes[1];
        if (authValue == 0x00) { // No authentication required
            
        } else if (authValue == 0x02) { // Password auth required
            
        } else if (authValue == 0xFF) { // all offered authentication methods were rejected
            
        } else { // everything is terrible
            
        }
        NSMutableData *requestData = [NSMutableData dataWithBytes:kConnectionPreambleBytes length:3];
        NSData *destinationPreamble = nil;
        NSData *destinationAddressOrHost = nil;
        if (self.destinationAddress) {
            const uint8_t addressPreamble[] = {0x01};
            destinationPreamble = [NSData dataWithBytes:addressPreamble length:1];
            destinationAddressOrHost = self.destinationAddress;
        } else if (self.destinationHost) {
            const uint8_t hostPreamble[] = {0x03};
            destinationPreamble = [NSData dataWithBytes:hostPreamble length:1];
            uint8_t *destinationLength = malloc(sizeof(uint8_t));
            destinationLength[0] = (uint8_t)self.destinationHost.length;
            NSMutableData *mutableDestinationData = [NSMutableData dataWithBytes:destinationLength length:1];
            free(destinationLength);
            [mutableDestinationData appendData:[self.destinationHost dataUsingEncoding:NSUTF8StringEncoding]];
            destinationAddressOrHost = mutableDestinationData;
        }
        [requestData appendData:destinationPreamble];
        [requestData appendData:destinationAddressOrHost];
        uint16_t bigEndianPort = EndianU16_NtoB(self.destinationPort);
        uint8_t firstPortByte = bigEndianPort & 0xFF;
        uint8_t secondPortByte = bigEndianPort >> 8;
        NSUInteger portBytesLength = 2;
        uint8_t *portBytes = malloc(sizeof(uint8_t) * portBytesLength);
        portBytes[0] = firstPortByte;
        portBytes[1] = secondPortByte;
        NSData *portData = [NSData dataWithBytes:portBytes length:portBytesLength];
        free(portBytes);
        [requestData appendData:portData];
        [sock writeData:requestData withTimeout:-1 tag:kDestinationWriteTag];
    } else if (tag == kDestinationReadTag) {
        NSLog(@"didRead kDestinationReadTag: %@", data.description);
        //uint8_t *bytes = (uint8_t*)[data bytes];
        if (self.delegate && [self.delegate respondsToSelector:@selector(socket:didConnectToHost:port:)]) {
            dispatch_async(self.delegateQueue, ^{
                @autoreleasepool {
                    [self.delegate socket:self didConnectToHost:self.destinationHost port:self.destinationPort];
                }
            });
        }
    } else if (tag == kDataReadTag) {
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
    NSLog(@"proxySocket disconnected from proxy %@:%d / destination %@:%d", self.proxyHost, self.proxyPort, self.destinationHost, self.self.destinationPort);

    if (self.delegate && [self.delegate respondsToSelector:@selector(socketDidDisconnect:withError:)]) {
        dispatch_async(self.delegateQueue, ^{
            @autoreleasepool {
                [self.delegate socketDidDisconnect:self withError:err];
            }
        });
    }
}

- (void) socketDidSecure:(GCDAsyncSocket *)sock {
    NSLog(@"didSecure proxy %@:%d / destination %@:%d", self.proxyHost, self.proxyPort, self.destinationHost, self.self.destinationPort);
    
    if (self.delegate && [self.delegate respondsToSelector:@selector(socketDidSecure:)]) {
        dispatch_async(self.delegateQueue, ^{
            @autoreleasepool {
                [self.delegate socketDidSecure:self];
            }
        });
    }
}


@end
