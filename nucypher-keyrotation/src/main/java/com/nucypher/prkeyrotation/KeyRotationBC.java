package com.nucypher.prkeyrotation;

import static org.apache.hadoop.hdfs.server.common.HdfsServerConstants.CRYPTO_XATTR_FILE_ENCRYPTION_INFO;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.URI;
import java.security.PrivilegedExceptionAction;
import java.util.*;

import com.google.protobuf.ByteString;
import com.nucypher.hadoop.hdfs.NuCypherExtClient;
import org.apache.commons.codec.binary.Hex;
import org.apache.hadoop.fs.*;
import org.apache.hadoop.hdfs.DFSClient;
import org.apache.hadoop.hdfs.DFSInputStream;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.apache.hadoop.hdfs.protocol.proto.HdfsProtos;
import org.apache.hadoop.hdfs.protocolPB.PBHelperClient;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.yarn.conf.YarnConfiguration;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

import com.nucypher.crypto.bbs98.WrapperBBS98;

import javax.ws.rs.core.UriBuilder;

public class KeyRotationBC {
	static void ReEncrypt(LocatedFileStatus status) {
		
	}

	public static void collectFileNames(DistributedFileSystem fs, String zonepath, List<String> names)
			throws IOException
	{
		FileStatus[] statuses = fs.listStatus(new Path(zonepath));
//		System.out.println("## cheking path " + new Path(zonepath).toString() + " iter " + statuses.length);
		for (FileStatus status : statuses) {
			String fname = zonepath + "/" + status.getPath().getName();
			if (status.isDirectory())
				collectFileNames(fs, fname, names);
			else
				names.add(fname);
		}
	}

	public static ByteString getByteString(byte[] bytes) {
		// return singleton to reduce object allocation
		return (bytes.length == 0) ? ByteString.EMPTY : ByteString.copyFrom(bytes);
	}

	public static HdfsProtos.PerFileEncryptionInfoProto convertPerFileEncInfo(
			FileEncryptionInfo info) {
		if (info == null) {
			return null;
		}
		return HdfsProtos.PerFileEncryptionInfoProto.newBuilder()
				.setKey(getByteString(info.getEncryptedDataEncryptionKey()))
				.setIv(getByteString(info.getIV()))
				.setEzKeyVersionName(info.getEzKeyVersionName())
				.build();
	}
	static void  runCmd(String cmd)
	{
		try {
			Process p = Runtime.getRuntime().exec(cmd);
			p.waitFor();
			BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
			String line=reader.readLine();

			while (line != null) {
				System.err.println(line);
				line = reader.readLine();
			}

		}
		catch(IOException e1) {}
		catch(InterruptedException e2) {}
	}


	public static void main(String[] args) {
/*
		runCmd("ls -la");
		runCmd("cat ./launch_container.sh");
		runCmd("cat ./default_container_executor.sh");
		runCmd("id");
*/
		try{
			final String oldKey = args[0];
			final String rekey = args[1];
			final String zonepath = args[2];
			final String newezkeyversion = args[3];
			final String pluginURL =  args[4];
			//int lower = 0, upper = 2000;
			byte[] rekeybytes = Hex.decodeHex(rekey.toCharArray());
			
			YarnConfiguration conf = new YarnConfiguration();
			conf.set("hadoop.client.ugi", "hdfs");
			//conf.set("hadoop.job.ugi", "hdfs");
			conf.set("hadoop.job.ugi", "hdfs");

			final DistributedFileSystem fs = (DistributedFileSystem)FileSystem.get(new URI(conf.get("fs.defaultFS")), conf, "hdfs");
			List<String> fileNames = new ArrayList<>();

			collectFileNames(fs, zonepath, fileNames);
			int index = 0;
			
//			//get dfsclient 
//	        Field dfsfield = DistributedFileSystem.class.getDeclaredField("dfs");
//	        dfsfield.setAccessible(true);
//	        DFSClient dfsclient = (DFSClient)dfsfield.get(fs);
	        DFSClient dfsClient = fs.getClient();

			final URI extURI  =  new URI(fs.getUri().getScheme() + "://" + pluginURL);

			System.err.println("connecting to ext service at " + extURI);

			String ticketCachePath =
					conf.get(CommonConfigurationKeys.KERBEROS_TICKET_CACHE_PATH);
			UserGroupInformation ugi =
					UserGroupInformation.getBestUGI(ticketCachePath, "hdfs");

			NuCypherExtClient extClient = ugi.doAs(new PrivilegedExceptionAction<NuCypherExtClient>() {
				@Override
				public NuCypherExtClient run() throws IOException {
					return new NuCypherExtClient(extURI, fs.getConf(), null);
				}
			});

			ECParameterSpec generationParam = ECNamedCurveTable.getParameterSpec("P-256");
	        WrapperBBS98 engine = new WrapperBBS98(generationParam, null);

			Map<String, Map<String, byte[]>> xAttrsToSet = new HashMap();
			for (String fname : fileNames){
				index++;
				//LocatedFileStatus status = iter.next();
//				if (index >= lower && index < upper) {
//					//ReEncrypt(status);
//					HdfsFileStatus hdfsstatus = dfsclient.getFileInfo(status.getPath().toString());
//					FileEncryptionInfo feinfo = hdfsstatus.getFileEncryptionInfo();
//					//engine.reEncrypt(param, rekey, feinfo.getEncryptedDataEncryptionKey());
//				}
	//			String fname = zonepath + "/" + fname;
				DFSInputStream f = dfsClient.open(fname);
				FileEncryptionInfo fe = f.getFileEncryptionInfo();
				// will not use this file in current job
				if (!fe.getEzKeyVersionName().equals(oldKey)) {
					continue;
				}

				//dfsClient.close();
				
				byte[] oldedek = fe.getEncryptedDataEncryptionKey();
				
				BigInteger rk = new BigInteger(rekeybytes);
				byte[] newedek = engine.reencrypt(rk, oldedek);
 
		//		System.out.println("##new edek:"+Hex.encodeHexString(newedek));

				FileEncryptionInfo newfe = new FileEncryptionInfo(fe.getCipherSuite(), fe.getCryptoProtocolVersion(),
												newedek, fe.getIV(), fe.getKeyName(), newezkeyversion);


				final HdfsProtos.PerFileEncryptionInfoProto proto = convertPerFileEncInfo(newfe);
				final byte[] protoBytes = proto.toByteArray();
				String pathName = "/.reserved/raw" + fname;
				if (!xAttrsToSet.containsKey(pathName))
					xAttrsToSet.put(pathName, new HashMap<String, byte[]>());
				xAttrsToSet.get(pathName).put(CRYPTO_XATTR_FILE_ENCRYPTION_INFO, protoBytes);
			}
			if (!xAttrsToSet.isEmpty()) {
				try {
					extClient.setXAttrs(xAttrsToSet, EnumSet.of(XAttrSetFlag.CREATE,
							XAttrSetFlag.REPLACE));
				} catch (Exception ec)
				{
					System.err.println("Cannot setXAttrs ot ZedoDB Extenstion at " + extURI + ": " +
							ec.toString());
					System.err.println("Falling back to default method");
					// fall back to default method

					for (String path : xAttrsToSet.keySet()) {
							Map<String, byte[]> currentSet = xAttrsToSet.get(path);
							for (String attrName : currentSet.keySet()) {
								byte[] attrValue = currentSet.get(attrName);
								fs.setXAttr(new Path(path), attrName, attrValue);
							}
						}
				}

			}
			dfsClient.close();
			extClient.close();
			
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
}
