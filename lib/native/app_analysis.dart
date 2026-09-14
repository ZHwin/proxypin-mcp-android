import 'package:flutter/services.dart';

import 'package:proxypin/network/util/logger.dart';

/// 应用分析原生插件封装
/// 提供设备已安装应用的列表、元数据（权限/组件/签名证书）、APK 导出能力
/// 供 MCP Server 使用，让 AI 客户端可以分析设备上的应用（无需 root）
class AppAnalysis {
  static const MethodChannel _methodChannel = MethodChannel('com.proxy/appAnalysis');

  /// 获取设备上已安装应用列表
  /// [includeSystemApps] 是否包含系统应用，[keyword] 按包名或应用名模糊过滤
  static Future<List<Map<String, dynamic>>> listApps({
    bool includeSystemApps = false,
    String keyword = '',
  }) async {
    try {
      final list = await _methodChannel.invokeListMethod<Map>('listApps', {
        "includeSystem": includeSystemApps,
        "keyword": keyword,
      });
      return list?.map((e) => Map<String, dynamic>.from(e)).toList() ?? [];
    } catch (e) {
      logger.e('[AppAnalysis] listApps error: $e');
      rethrow;
    }
  }

  /// 获取指定应用的详细元数据（版本、权限、四大组件、签名证书等）
  static Future<Map<String, dynamic>> getAppMetadata(String packageName) async {
    try {
      final result = await _methodChannel
          .invokeMethod<Map>('getAppMetadata', {"packageName": packageName});
      return Map<String, dynamic>.from(result ?? {});
    } catch (e) {
      logger.e('[AppAnalysis] getAppMetadata error: $e');
      rethrow;
    }
  }

  /// 导出指定应用的 APK 到应用缓存目录
  /// [includeSplits] 为 true 时导出包含所有 split APK 的 zip 包
  /// 返回 {path, fileName, size, packageName, ...}
  static Future<Map<String, dynamic>> exportApk(String packageName, {bool includeSplits = false}) async {
    try {
      final result = await _methodChannel.invokeMethod<Map>('exportApk', {
        "packageName": packageName,
        "includeSplits": includeSplits,
      });
      return Map<String, dynamic>.from(result ?? {});
    } catch (e) {
      logger.e('[AppAnalysis] exportApk error: $e');
      rethrow;
    }
  }
}
