Pod::Spec.new do |s|
  s.name             = 'crypto_lib'
  s.version          = '0.1.0'
  s.summary          = 'Rust-based cryptographic library for iOS'
  s.description      = <<-DESC
    A high-performance cryptographic library written in Rust with Swift bindings.
    Supports RSA encryption/decryption, AES-GCM encryption/decryption, and ECC operations.
  DESC
  
  s.homepage         = 'https://github.com/tianqianl/rustCrypto'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'tianqianl' => 'tianqianl@example.com' }
  s.source           = { :git => 'https://github.com/tianqianl/rustCrypto.git', :tag => s.version.to_s }
  
  s.ios.deployment_target = '12.0'
  s.swift_version = '5.0'
  
  s.source_files = 'CryptoLib.swift'
  
  # 框架文件
  s.vendored_frameworks = 'Frameworks/crypto_lib.xcframework'
  
  # 资源文件
  s.resources = ['Assets/*']
  
  # 系统框架
  s.frameworks = 'Foundation', 'Security'
  
  # 如果需要依赖其他库
  s.dependency 'SwiftBase58', '~> 1.0'
  
  # 静态库
  s.static_framework = true
end
