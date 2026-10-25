#import <Foundation/Foundation.h>
#import <Mobilecore/Mobilecore.h>

NS_ASSUME_NONNULL_BEGIN

/// gomobile marks (string,error) results nonnull even when its Objective-C
/// implementation returns nil on error. This nullable adapter ensures Swift
/// checks NSError before attempting to bridge that result into String.
@interface VowifiGoBridge : NSObject
+ (nullable NSString *)command:(MobilecoreEngine *)engine
                      request:(NSString *)request
                        error:(NSError * _Nullable * _Nullable)error;
@end

NS_ASSUME_NONNULL_END
