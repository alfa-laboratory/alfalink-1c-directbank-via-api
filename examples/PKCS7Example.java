/**
 * Copyright 2004-2012 Crypto-Pro. All rights reserved.
 * Программный код, содержащийся в этом файле, предназначен
 * для целей обучения. Может быть скопирован или модифицирован
 * при условии сохранения абзацев с указанием авторства и прав.
 *
 * Данный код не может быть непосредственно использован
 * для защиты информации. Компания Крипто-Про не несет никакой
 * ответственности за функционирование этого кода.
 */
package CAdES;

import CAdES.configuration.Configuration;
import CAdES.configuration.SimpleConfiguration;
import CAdES.configuration.container.Container2012_256;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.util.Store;

import ru.CryptoPro.CAdES.CAdESSignature;
import ru.CryptoPro.CAdES.tools.CAdESUtility;
import ru.CryptoPro.CAdES.tools.verifier.GostContentSignerProvider;
import ru.CryptoPro.CAdES.tools.verifier.GostDigestCalculatorProvider;

import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.tools.Array;

import java.io.FileInputStream;
import java.security.PrivateKey;
import java.security.cert.*;
import java.util.*;

/**
 * Пример формирования простой подписи PKCS7 с помощью
 * BouncyCastle и проверки CAdES API.
 * 
 * 20/04/2012
 *
 */
public class PKCS7Example {

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		// Этот вызов делается автоматически при использовании
		// класса CAdESSignature, однако тут необходимо его выполнить
		// специально, т.к. начинаем работать с ГОСТ без упоминания
		// CAdESSignature.

		CAdESUtility.initJCPAlgorithms();
		
		try {
		
			List<X509Certificate> chain  = new ArrayList<X509Certificate>();
			Set<X509Certificate> certSet = new HashSet<X509Certificate>(chain);

			PrivateKey privateKey = Configuration.loadConfiguration(
				new Container2012_256(), chain);
			
			// Сертификат подписи - первый в списке.
			X509Certificate signerCert = chain.iterator().next();
			Store certStore = new JcaCertStore(chain);
			
			// Подготавливаем подпись.
			CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

			ContentSigner contentSigner = new GostContentSignerProvider(
				privateKey, JCP.PROVIDER_NAME);

			SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder(
				new GostDigestCalculatorProvider(privateKey, JCP.PROVIDER_NAME))
                    .build(contentSigner, signerCert);

			generator.addSignerInfoGenerator(signerInfoGenerator);
			generator.addCertificates(certStore);
			  
			// Создаем совмещенную подпись PKCS7.
			CMSProcessable content = new CMSProcessableByteArray(Configuration.DATA);
			CMSSignedData signedData = generator.generate((CMSTypedData) content, true);
			 
			// Сформированная подпись.
			byte[] pkcs7 = signedData.getEncoded();
			
			Array.writeFile(SimpleConfiguration.TEMP_PATH + "/pkcs7.bin", pkcs7);
			
			// Подпись в тесте была совмещенная, потому данные равны null. Предположим, что
			// подписей несколько, тогда лучше указать тип null и положиться на самоопределение
			// типа подписи.
			CAdESSignature pkcs7Signature = new CAdESSignature(pkcs7, null, null);
			
			// Если задан CRL, то читаем его из файла.
			if (SimpleConfiguration.CRL_PATH != null) {
							
				X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509")
					.generateCRL(new FileInputStream(SimpleConfiguration.CRL_PATH));
							
				pkcs7Signature.verify(certSet, Collections.singleton(crl));
							
			} else {
				pkcs7Signature.verify(certSet);
			}
			
			Configuration.printSignatureInfo(pkcs7Signature);
			
		} catch (Exception e) {
            Configuration.printCAdESException(e);
        }
	}
}
