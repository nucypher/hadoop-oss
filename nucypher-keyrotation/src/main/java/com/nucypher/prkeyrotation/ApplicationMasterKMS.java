package com.nucypher.prkeyrotation;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.net.util.Base64;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.crypto.key.KeyProvider;
import org.apache.hadoop.crypto.key.KeyProvider.KeyVersion;
import org.apache.hadoop.crypto.key.KeyProviderFactory;
import org.apache.hadoop.crypto.key.kms.KMSClientProvider;
import org.apache.hadoop.fs.*;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.hdfs.DFSClient;
import org.apache.hadoop.hdfs.DFSInputStream;
import org.apache.hadoop.hdfs.DistributedFileSystem;
import org.apache.hadoop.hdfs.protocol.EncryptionZone;
import org.apache.hadoop.io.IOUtils;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.yarn.api.ApplicationConstants;
import org.apache.hadoop.yarn.api.ApplicationConstants.Environment;
import org.apache.hadoop.yarn.api.protocolrecords.AllocateResponse;
import org.apache.hadoop.yarn.api.records.*;
import org.apache.hadoop.yarn.client.api.AMRMClient;
import org.apache.hadoop.yarn.client.api.AMRMClient.ContainerRequest;
import org.apache.hadoop.yarn.client.api.NMClient;
import org.apache.hadoop.yarn.conf.YarnConfiguration;
import org.apache.hadoop.yarn.util.Apps;
import org.apache.hadoop.yarn.util.ConverterUtils;
import org.apache.hadoop.yarn.util.Records;
import org.codehaus.jackson.map.ObjectMapper;



public class ApplicationMasterKMS {
	Configuration conf = new YarnConfiguration();
	
	private void setupAppJar(Path jarPath, LocalResource appJar) throws IOException {
		FileStatus jarStat = FileSystem.get(conf).getFileStatus(jarPath);
		appJar.setResource(ConverterUtils.getYarnUrlFromPath(jarPath));
		appJar.setSize(jarStat.getLen());
		appJar.setTimestamp(jarStat.getModificationTime());
		appJar.setType(LocalResourceType.FILE);
		appJar.setVisibility(LocalResourceVisibility.APPLICATION);
	}

  private void setupExtJar(String exclasspath, Map<String, LocalResource> localResources, String appId) throws IOException {
    String[] excparray = exclasspath.split(",");
    FileSystem fs = FileSystem.get(conf);
    for (String cp: excparray) {
      String strippedCp = Paths.get(cp).getFileName().toString();
      addToLocalResources(fs,
          "." + File.separator + strippedCp , strippedCp,  appId, localResources, null);
    }
  }
  private void addToLocalResources(FileSystem fs, String fileSrcPath,
                                   String fileDstPath, String appId, Map<String, LocalResource> localResources,
                                   String resources) throws IOException {
    String suffix =
        "prkeyrotation" + "/" + appId + "/" + fileDstPath;
    Path dst =
        new Path(fs.getHomeDirectory(), suffix);
    if (fileSrcPath == null) {
      FSDataOutputStream ostream = null;
      try {
        ostream = FileSystem
            .create(fs, dst, new FsPermission((short) 0710));
        ostream.writeUTF(resources);
      } finally {
        org.apache.commons.io.IOUtils.closeQuietly(ostream);
      }
    } else {
      fs.copyFromLocalFile(new Path(fileSrcPath), dst);
    }
    FileStatus scFileStatus = fs.getFileStatus(dst);
    LocalResource scRsrc =
        LocalResource.newInstance(
            ConverterUtils.getYarnUrlFromPath(dst),
            LocalResourceType.FILE, LocalResourceVisibility.APPLICATION,
            scFileStatus.getLen(), scFileStatus.getModificationTime());
    localResources.put(fileDstPath, scRsrc);
  }
	
	private void setupAppEnv(Map<String, String> appEnv, String exclasspath) {
		for (String c: conf.getStrings(
				YarnConfiguration.YARN_APPLICATION_CLASSPATH, 
				YarnConfiguration.DEFAULT_YARN_APPLICATION_CLASSPATH)) {
			Apps.addToEnvironment(appEnv, Environment.CLASSPATH.name(), c.trim());
		}
		Apps.addToEnvironment(appEnv, Environment.CLASSPATH.name(),
				Environment.PWD.$() + File.separator + "*");
	}

	private  void collectFileNames(DistributedFileSystem fs, String zonepath, List<String> names)
			throws IOException
	{
		FileStatus[] statuses = fs.listStatus(new Path(zonepath));
		// System.out.println("## cheking path " + new Path(zonepath).toString() + " iter " + statuses.length);
		for (FileStatus status : statuses) {
			String fname = zonepath + "/" + status.getPath().getName();
			if (status.isDirectory())
				collectFileNames(fs, fname, names);
			else
				names.add(fname);
		}
	}


  void runCmd(String cmd)
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

	public void run(String[] args) throws Exception {
    //runCmd("ls -la");
    //runCmd("cat ./launch_container.sh");
    //runCmd("cat ./default_container_executor.sh");




    int n = 0;
	//	final Path jarPath = new Path(args[0]);

		final String zonepaths = args[0];
		final String exclasspath = args[1];
		final String globalKMS = args[2];

		final String providerURIStrings = args.length > 2 ? args[3] : "";

		final String pluginURL =  (args.length > 3) ? args[4] : "";

		List<URI> providerURIs = new ArrayList<>();

		if (providerURIStrings.isEmpty())
			throw new IllegalArgumentException("Key providers should be provided");

		{
			String[] providers = providerURIStrings.split(",");
			for (String provider : providers) {
				providerURIs.add(new URI(provider));
			}
		}


		Configuration conf = new YarnConfiguration();
		
		AMRMClient<ContainerRequest> rmClient = AMRMClient.createAMRMClient();
		rmClient.init(conf);
		rmClient.start();
		
		NMClient nmClient = NMClient.createNMClient();
		nmClient.init(conf);
		nmClient.start();
		
		System.out.println("registerApplicationMaster 0");
		rmClient.registerApplicationMaster("", 0, "");
		System.out.println("registerApplicationMaster 1");
		System.out.println("##ex classpath:"+exclasspath);
		System.out.println("##global kms:"+globalKMS);

		///// Generate Re-Encrypt Key //////////////////////////////////////
		//List<String> zonepathlist = new ArrayList<String>();
		List<String> oldglist = new ArrayList<String>();
		List<HashMap<String, String>> rekeylist = new ArrayList<>();
		List<String> newezkeylist = new ArrayList<String>();
		
		String[] zonepatharray = zonepaths.split(",");
		List<String> zonepathlist = Arrays.asList(zonepatharray);

		for (String zonepath: zonepatharray) {
			List<KeyProvider> keyProvider = new ArrayList<>();
			for (URI providerURI : providerURIs) {
				keyProvider.add(KeyProviderFactory.get(providerURI, conf));
			}

			KeyProvider curProvider1 = null;
			if (keyProvider.size() > 0) {
				curProvider1 = keyProvider.get(0);
			}
			System.out.println("##provider class:" + curProvider1.getClass().getName());

			KMSClientProvider curProvider = (KMSClientProvider) curProvider1;

//			KeyPairVersion newKeyPairVersion = curProvider.rollNewVersionPair("keyrotation");
//			byte[] newskbytes = newKeyPairVersion.getPrivateMaterial().getMaterial();

			byte[] oldskbytes = null;
			String keyname = null;
			KeyVersion oldkeyversion = null;

			DistributedFileSystem fs = (DistributedFileSystem) FileSystem.get(conf);

			EncryptionZone zoneInfo = fs.getEZForPath(new Path(zonepath));

			keyname = zoneInfo.getKeyName();

			KeyVersion newkeyversion = curProvider.rollNewVersion(keyname);
			newezkeylist.add(newkeyversion.getVersionName());

			List<String> fileNames = new ArrayList<>();

			collectFileNames(fs, zonepath, fileNames);

			System.out.println("##for zone path:" + new Path(zonepath).toString() + " collected total " +
				fileNames.size() + " files ");


			DFSClient dfsClient = fs.getClient();
			HashMap<String, String> zoneReKeys = new HashMap<>();
			for (String fname : fileNames){
				DFSInputStream f = dfsClient.open(fname);
				FileEncryptionInfo fe = f.getFileEncryptionInfo();
				String ezKeyVersionName = fe.getEzKeyVersionName();
     //   System.out.println("##got key name " + ezKeyVersionName + " for " + fname);
				// already have this key, no need to proceed
				if (zoneReKeys.containsKey(ezKeyVersionName))
					continue;
				//KeyVersion ezKeyVersion = curProvider.getCurrentKey(ezKeyVersionName);
//	        	KeyPairVersion keyPairVersion = curProvider.getCurrentKeyPair(ezKeyVersionName);
//	        	oldskbytes = keyPairVersion.getPrivateMaterial().getMaterial();

				KeyVersion ezKeyVersion = curProvider.getKeyVersion(ezKeyVersionName);
				oldskbytes = ezKeyVersion.getMaterial();
				oldkeyversion = ezKeyVersion;

				if (oldskbytes == null) {
					System.out.println("##oldskbytes is null");
					return;
				}

//	        System.out.println("##oldskbytes:"+Hex.encodeHexString(oldskbytes));
//	        PrivateKey newskspec = new PrivateKeySpec(newkeyversion.getMaterial(), "BBS98");
//	        PrivateKey oldskspec = new PrivateKeySpec(oldskbytes, "BBS98");
//	        System.out.println(PrivateKeySpec.class.getResource(""));
//	        System.out.println("##oldsk spec:"+Hex.encodeHexString(oldskspec.getEncoded()));
//
//	        ECParameterSpec generationParam = ECNamedCurveTable.getParameterSpec("P-256");
//	        WrapperBBS98 engine = new WrapperBBS98(generationParam, null);
//	        
//	       
				UserGroupInformation currentUgi = UserGroupInformation.getCurrentUser();

				// http://localhost:16000/kms/v1/keysrcdstversion/ztestkey%403/ztestkey%404/_rek?rek_op=generate&user.name=hduser
				String kmsurl = "http://" + globalKMS + "/kms/v1/keysrcdstversions/" + oldkeyversion.getVersionName() + "/" +
						newkeyversion.getVersionName() + "/_rek?rek_op=generate&user.name=" + currentUgi.getShortUserName();
				System.out.println("##kmsurl:" + kmsurl);

				URL url = new URL(kmsurl);
				HttpURLConnection connection = (HttpURLConnection) url.openConnection();

				connection.connect();
				// 取得输入流，并使用Reader读取
				//	     BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream(),"utf-8"));//设置编码,否则中文乱码
				//	     System.out.println("=============================");
				//	     System.out.println("Contents of get request");
				//	     System.out.println("=============================");
				//	     String lines;
				//	     while ((lines = reader.readLine()) != null){
				//	             //lines = new String(lines.getBytes(), "utf-8");
				//	     System.out.println(lines);
				//	     }

				ObjectMapper mapper = new ObjectMapper();
				InputStream is = null;
				List<Map<String, String>> ret = null;
				try {
					is = connection.getInputStream();
					ret = mapper.readValue(is, List.class);
				} finally {
					IOUtils.closeStream(is);
				}

				connection.disconnect();

				String rekencode = "";
				for (Map<String, String> map : ret) {
					for (Map.Entry<String, String> entry : map.entrySet()) {
						System.out.println("##ret key:" + entry.getKey());
						System.out.println("##ret value:" + entry.getValue());
						rekencode = entry.getValue();
					}
				}

				byte[] rekbytes = Base64.decodeBase64(rekencode);

				String rekey = Hex.encodeHexString(rekbytes);
				System.out.println("##rekey:" + rekey);
				zoneReKeys.put(ezKeyVersionName, rekey);
				++n;
			}
      System.out.println("## total " + zoneReKeys.size() + " for zone");
			rekeylist.add(zoneReKeys);
		}
        
        
		///////////////// start containers //////////////////////////
		Priority priority = Records.newRecord(Priority.class);
		priority.setPriority(0);
		
		Resource capability = Records.newRecord(Resource.class);
		capability.setMemory(256);
		capability.setVirtualCores(1);

    int index = 0;
    List<String> oldKeys = new ArrayList<>(rekeylist.get(index).keySet());

		for (int i = 0; i < n; i++) {
			ContainerRequest containerAsk = new ContainerRequest(capability, null, null, priority);
			System.out.println("Making res-req " + i);
			rmClient.addContainerRequest(containerAsk);
		}
		
		int responseId = 0;
		int completedContainers = 0;

		LocalResource jarResource = Records.newRecord(LocalResource.class);
		//setupAppJar(jarPath, jarResource);
		Map<String, LocalResource> localResources = new HashMap<>();
	//	localResources.put("prkeyrotation.jar", jarResource);
		setupExtJar(exclasspath, localResources, "prkeyrotation");

		Map<String,String> appEnv = new HashMap<>();
		setupAppEnv(appEnv, exclasspath);

		for (String env : appEnv.keySet())
		{
			System.out.println("env: " + env + " = " + appEnv.get(env));
		}

		System.out.println("local resource: " + jarResource.toString());

    int oldKeyIndex = 0;
		while (completedContainers < n) {
			AllocateResponse response = rmClient.allocate(responseId++);
			for (Container container : response.getAllocatedContainers()) {
				System.out.println("## starting job {" +  oldKeys.get(oldKeyIndex) + " } -> { " +
						newezkeylist.get(index) + "}");
				ContainerLaunchContext ctx = Records.newRecord(ContainerLaunchContext.class);
				ctx.setCommands(
						Collections.singletonList(
						//"/usr/bin/java"+
						Environment.JAVA_HOME.$$() + "/bin/java" + 
						" -Xmx1024M"+
						" KeyRotationBC"+
						" " + oldKeys.get(oldKeyIndex) +
						" " + rekeylist.get(index).get(oldKeys.get(oldKeyIndex)) +
						" " + zonepathlist.get(index) +
						" " + newezkeylist.get(index) +
						" "	+ pluginURL +
						" 1>" + ApplicationConstants.LOG_DIR_EXPANSION_VAR + "/stdout" +
						" 2>" + ApplicationConstants.LOG_DIR_EXPANSION_VAR + "/stderr"));

        ctx.setLocalResources(localResources);
				ctx.setEnvironment(appEnv);

				System.out.println("Launching container " + container.getId() + " at " + container.getNodeHttpAddress());
				nmClient.startContainer(container, ctx);
				if (++oldKeyIndex == oldKeys.size()) {
					if (++index >= zonepathlist.size())
						break;
					oldKeys = new ArrayList<>(rekeylist.get(index).keySet());
					oldKeyIndex = 0;
				}
			}
			
			for (ContainerStatus status : response.getCompletedContainersStatuses()) {
				if (status.getState() == ContainerState.COMPLETE)
					completedContainers++;
				System.out.println("Completed container " + status.getContainerId() + " "
					+ completedContainers + " of " + n + ": " + status);
			}
			Thread.sleep(100);
		}
		
		rmClient.unregisterApplicationMaster(FinalApplicationStatus.SUCCEEDED, "", "");
		
	}
	
	public static void main(String[] args) throws Exception {
		ApplicationMasterKMS appmaster = new ApplicationMasterKMS();
		appmaster.run(args);
	}
}
