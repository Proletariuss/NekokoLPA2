Pod::Spec.new do |s|
  s.name = 'proletarius_vowifi'
  s.version = '0.1.0'
  s.summary = 'Reader-backed IMS, CallKit and native PCM audio for NekokoLPA2.'
  s.description = 'In-process Go IMS engine with a cancellable Flutter SIM bridge and iOS call audio.'
  s.homepage = 'https://github.com/iebb/NekokoLPA2'
  s.license = { :type => 'MIT', :file => '../LICENSE' }
  s.author = { 'Proletarius' => 'Proletarius' }
  s.source = { :path => '.' }
  s.source_files = 'Classes/**/*.{h,m,swift}'
  s.resources = 'Resources/MobileCoreNotices.txt'
  s.dependency 'Flutter'
  s.platform = :ios, '15.6'
  s.swift_version = '5.0'
  s.frameworks = 'AVFoundation', 'CallKit', 'UIKit'
  s.vendored_frameworks = 'Frameworks/Mobilecore.xcframework'
  s.vendored_libraries = 'Frameworks/libopencore-amrnb.a'
  s.libraries = 'c++'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
end
