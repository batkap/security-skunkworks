import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  const secureStorage = FlutterSecureStorage();
  await secureStorage.write(key: 'boot', value: 'ok');
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString('authToken', 'token-value');
  final client = HttpClient();
  client.badCertificateCallback = (_, __, ___) => true;
  runApp(const SizedBox.shrink());
}
