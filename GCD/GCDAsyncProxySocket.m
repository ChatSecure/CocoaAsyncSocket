//
//  GCDAsyncProxySocket.m
//  OnionKit
//
//  Created by Christopher Ballinger on 11/19/13.
//  Copyright (c) 2013 ChatSecure. All rights reserved.
//

#import "GCDAsyncProxySocket.h"
#import "Endian.h"


// Define various socket tags
#define SOCKS_OPEN             101
#define SOCKS_CONNECT          102
#define SOCKS_CONNECT_REPLY_1  103
#define SOCKS_CONNECT_REPLY_2  104

// Timeouts
#define TIMEOUT_CONNECT       8.00
#define TIMEOUT_READ          5.00
#define TIMEOUT_TOTAL        80.00

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

#pragma mark Overridden methods

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

- (void) writeData:(NSData *)data withTimeout:(NSTimeInterval)timeout tag:(long)tag {
    // TODO remove this for performance
    if (tag == SOCKS_OPEN || tag == SOCKS_CONNECT || tag == SOCKS_CONNECT_REPLY_1 || tag == SOCKS_CONNECT_REPLY_2) {
        NSLog(@"This tag is reserved and won't work: %ld", tag);
        return;
    }
    [self.proxySocket writeData:data withTimeout:timeout tag:tag];
}

- (void) readDataWithTimeout:(NSTimeInterval)timeout tag:(long)tag {
    [self.proxySocket readDataWithTimeout:timeout tag:tag];
}

- (void) startTLS:(NSDictionary *)tlsSettings {
    NSMutableDictionary *settings = [NSMutableDictionary dictionaryWithDictionary:tlsSettings];
    NSString *peerName = self.destinationHost;
    [settings setObject:peerName forKey:(NSString *)kCFStreamSSLPeerName];
    [self.proxySocket startTLS:settings];
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark SOCKS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Sends the SOCKS5 open/handshake/authentication data, and starts reading the response.
 * We attempt to gain anonymous access (no authentication).
 **/
- (void)socksOpen
{
	//XMPPLogTrace();
	
	//      +-----+-----------+---------+
	// NAME | VER | NMETHODS  | METHODS |
	//      +-----+-----------+---------+
	// SIZE |  1  |    1      | 1 - 255 |
	//      +-----+-----------+---------+
	//
	// Note: Size is in bytes
	//
	// Version    = 5 (for SOCKS5)
	// NumMethods = 1
	// Method     = 0 (No authentication, anonymous access)
    
	NSUInteger byteBufferLength = 3;
	uint8_t *byteBuffer = malloc(byteBufferLength * sizeof(uint8_t));
	
	uint8_t version = 5; // VER
	byteBuffer[0] = version;
	
	uint8_t numMethods = 1;
	byteBuffer[1] = numMethods;
	
	uint8_t method = 0;
	byteBuffer[2] = method;
	
	NSData *data = [NSData dataWithBytesNoCopy:byteBuffer length:byteBufferLength freeWhenDone:YES];
	NSLog(@"TURNSocket: SOCKS_OPEN: %@", data);
    
	[self.proxySocket writeData:data withTimeout:-1 tag:SOCKS_OPEN];
	
	//      +-----+--------+
	// NAME | VER | METHOD |
	//      +-----+--------+
	// SIZE |  1  |   1    |
	//      +-----+--------+
	//
	// Note: Size is in bytes
	//
	// Version = 5 (for SOCKS5)
	// Method  = 0 (No authentication, anonymous access)
	
	[self.proxySocket readDataToLength:2 withTimeout:TIMEOUT_READ tag:SOCKS_OPEN];
}

/**
 * Sends the SOCKS5 connect data (according to XEP-65), and starts reading the response.
 **/
- (void)socksConnect
{
	//      +-----+-----+-----+------+------+------+
	// NAME | VER | CMD | RSV | ATYP | ADDR | PORT |
	//      +-----+-----+-----+------+------+------+
	// SIZE |  1  |  1  |  1  |  1   | var  |  2   |
	//      +-----+-----+-----+------+------+------+
	//
	// Note: Size is in bytes
	//
	// Version      = 5 (for SOCKS5)
	// Command      = 1 (for Connect)
	// Reserved     = 0
	// Address Type = 3 (1=IPv4, 3=DomainName 4=IPv6)
	// Address      = P:D (P=LengthOfDomain D=DomainWithoutNullTermination)
	// Port         = 0
    
	uint byteBufferLength = (uint)(4 + 1 + [self.destinationHost length] + 2);
	void *byteBuffer = malloc(byteBufferLength);
	
	UInt8 ver = 5;
	memcpy(byteBuffer+0, &ver, sizeof(ver));
	
	UInt8 cmd = 1;
	memcpy(byteBuffer+1, &cmd, sizeof(cmd));
	
	UInt8 rsv = 0;
	memcpy(byteBuffer+2, &rsv, sizeof(rsv));
	

	UInt8 atyp = 3;
    
	memcpy(byteBuffer+3, &atyp, sizeof(atyp));
	
    NSData *hostData = [self.destinationHost dataUsingEncoding:NSUTF8StringEncoding];
	UInt8 hostLength = [hostData length];
	memcpy(byteBuffer+4, &hostLength, sizeof(hostLength));
	
	memcpy(byteBuffer+5, [hostData bytes], hostLength);
	
	UInt16 port = 0;
	memcpy(byteBuffer+5+hostLength, &port, sizeof(port));
	
	NSData *data = [NSData dataWithBytesNoCopy:byteBuffer length:byteBufferLength freeWhenDone:YES];
	NSLog(@"TURNSocket: SOCKS_CONNECT: %@", data);
	
	[self.proxySocket writeData:data withTimeout:-1 tag:SOCKS_CONNECT];
	
	//      +-----+-----+-----+------+------+------+
	// NAME | VER | REP | RSV | ATYP | ADDR | PORT |
	//      +-----+-----+-----+------+------+------+
	// SIZE |  1  |  1  |  1  |  1   | var  |  2   |
	//      +-----+-----+-----+------+------+------+
	//
	// Note: Size is in bytes
	//
	// Version      = 5 (for SOCKS5)
	// Reply        = 0 (0=Succeeded, X=ErrorCode)
	// Reserved     = 0
	// Address Type = 3 (1=IPv4, 3=DomainName 4=IPv6)
	// Address      = P:D (P=LengthOfDomain D=DomainWithoutNullTermination)
	// Port         = 0
	//
	// It is expected that the SOCKS server will return the same address given in the connect request.
	// But according to XEP-65 this is only marked as a SHOULD and not a MUST.
	// So just in case, we'll read up to the address length now, and then read in the address+port next.
	
	[self.proxySocket readDataToLength:5 withTimeout:TIMEOUT_READ tag:SOCKS_CONNECT_REPLY_1];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#pragma mark AsyncSocket Delegate Methods
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

- (void)socket:(GCDAsyncSocket *)sock didConnectToHost:(NSString *)host port:(UInt16)port
{
    NSLog(@"proxySocket did connect to %@:%d", host, port);
	//XMPPLogTrace();
	
	// Start the SOCKS protocol stuff
	[self socksOpen];
}

- (void)socket:(GCDAsyncSocket *)sock didReadData:(NSData *)data withTag:(long)tag
{
    NSLog(@"did read tag[%ld] data: %@", tag, data);
	//XMPPLogTrace();
	
	if (tag == SOCKS_OPEN)
	{
        NSAssert(data.length == 2, @"SOCKS_OPEN reply length must be 2!");
		// See socksOpen method for socks reply format
		uint8_t *bytes = (uint8_t*)[data bytes];
		UInt8 ver = bytes[0];
		UInt8 mtd = bytes[1];
		
		NSLog(@"TURNSocket: SOCKS_OPEN: ver(%o) mtd(%o)", ver, mtd);
		
		if(ver == 5 && mtd == 0)
		{
			[self socksConnect];
		}
		else
		{
			// Some kind of error occurred.
			// The proxy probably requires some kind of authentication.
			[self.proxySocket disconnect];
		}
	}
	else if (tag == SOCKS_CONNECT_REPLY_1)
	{
		// See socksConnect method for socks reply format
		NSAssert(data.length == 5, @"SOCKS_CONNECT_REPLY_1 length must be 5!");
		NSLog(@"TURNSocket: SOCKS_CONNECT_REPLY_1: %@", data);
		uint8_t *bytes = (uint8_t*)[data bytes];
        
		UInt8 ver = bytes[0];
		UInt8 rep = bytes[1];
		
		NSLog(@"TURNSocket: SOCKS_CONNECT_REPLY_1: ver(%o) rep(%o)", ver, rep);
		
		if(ver == 5 && rep == 0)
		{
			// We read in 5 bytes which we expect to be:
			// 0: ver  = 5
			// 1: rep  = 0
			// 2: rsv  = 0
			// 3: atyp = 3
			// 4: size = size of addr field
			//
			// However, some servers don't follow the protocol, and send a atyp value of 0.
			
			UInt8 atyp = bytes[3];
			
			if (atyp == 3)
			{
				UInt8 addrLength = bytes[4];
				UInt8 portLength = 2;
				
				NSLog(@"TURNSocket: addrLength: %o", addrLength);
				NSLog(@"TURNSocket: portLength: %o", portLength);
				
				[self.proxySocket readDataToLength:(addrLength+portLength)
								  withTimeout:TIMEOUT_READ
										  tag:SOCKS_CONNECT_REPLY_2];
			}
			else if (atyp == 0)
			{
				// The size field was actually the first byte of the port field
				// We just have to read in that last byte
				[self.proxySocket readDataToLength:1 withTimeout:TIMEOUT_READ tag:SOCKS_CONNECT_REPLY_2];
			}
			else
			{
				NSLog(@"TURNSocket: Unknown atyp field in connect reply");
				[self.proxySocket disconnect];
			}
		}
		else
		{
			// Some kind of error occurred.
			[self.proxySocket disconnect];
		}
	}
	else if (tag == SOCKS_CONNECT_REPLY_2)
	{
		// See socksConnect method for socks reply format
		
		NSLog(@"TURNSocket: SOCKS_CONNECT_REPLY_2: %@", data);
		
        if (self.delegate && [self.delegate respondsToSelector:@selector(socket:didConnectToHost:port:)]) {
            dispatch_async(self.delegateQueue, ^{
                @autoreleasepool {
                    [self.delegate socket:self didConnectToHost:self.destinationHost port:self.destinationPort];
                }
            });
        }
	}
    else {
        if (self.delegate && [self.delegate respondsToSelector:@selector(socket:didReadData:withTag:)]) {
            dispatch_async(self.delegateQueue, ^{
                @autoreleasepool {
                    [self.delegate socket:self didReadData:data withTag:-1];
                }
            });
        }
    }
}


#pragma mark GCDAsyncSocketDelegate methods


- (void) socket:(GCDAsyncSocket *)sock didWriteDataWithTag:(long)tag {
    if (self.delegate && [self.delegate respondsToSelector:@selector(socket:didWriteDataWithTag:)]) {
        dispatch_async(self.delegateQueue, ^{
            @autoreleasepool {
                [self.delegate socket:self didWriteDataWithTag:tag];
            }
        });
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
