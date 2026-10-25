#import "VowifiGoBridge.h"

@implementation VowifiGoBridge
+ (nullable NSString *)command:(MobilecoreEngine *)engine
                      request:(NSString *)request
                        error:(NSError * _Nullable * _Nullable)error {
    NSError *failure = nil;
    NSString *value = [engine command:request error:&failure];
    if (failure != nil) {
        if (error != nil) { *error = failure; }
        return nil;
    }
    if (value == nil) {
        if (error != nil) {
            *error = [NSError errorWithDomain:@"ProletariusVoWiFi" code:1
                                    userInfo:@{NSLocalizedDescriptionKey: @"The IMS engine returned no response."}];
        }
        return nil;
    }
    return value;
}
@end
