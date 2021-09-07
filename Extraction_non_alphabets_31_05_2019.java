package prevFeaturesPlusEntropy;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.io.FilenameUtils;

import whoIsPackage.WhoisTest;

public class Extraction_non_alphabets_31_05_2019 {

	private void extractFeatures(File inpFile) {
		// TODO Auto-generated method stub
		try {

			BufferedReader br = new BufferedReader(new FileReader(inpFile));

			String[] sec_sen_words = { "confirm", "account", "banking", "secure", "ebayisapi", "webscr", "login",
					"signin" };

			String eachUrl = null;
			
			//AFTER FEATURE SELECTION BY FEATURE IMPORTANCE FOR  IMBALANCED DATASET
			File fileNonAlphabet = new File("features.csv");
			
			//AFTER FEATURE SELECTION BY FEATURE IMPORTANCE FOR BALANCED DATASET
			//File fileNonAlphabet = new File("features_5000.csv");
			
			char[] nonAlphaNumeric = extractNonAlphaNumericChar(fileNonAlphabet);
			
			/*Start of Balanced and imbalanced dataset vecFile
			 * Calculate Entropy Only. Output file is vecFile
			 */
			//CALCULATION WITH ENTROPY VECTOR FOR IMBALANCED DATASETS
			//File vecFile = new File("leg_vec_non_alpha_numericBy_FeatSelect.csv");
			//File vecFile = new File("phish_vec_non_alpha_numericBy_FeatSelect.csv");
			
			//CALCULATION WITH ENTROPY VECTOR FOR BALANCED DATASETS
			//File vecFile = new File("phish_vec_non_alpha_numericBy_FeatSelect_5000.csv");
			File vecFile = new File("leg_vec_non_alpha_numericBy_FeatSelect_5000.csv");
			
			/*End of Balanced and imbalanced dataset vecFile
			 * */
			
			BufferedWriter bw = new BufferedWriter(new FileWriter(vecFile));

			ArrayList<String> resList = new ArrayList<String>();
			while ((eachUrl = br.readLine()) != null) {

				/*
				 * Start For No protocol Urls Add https:
				 */
				// if (!(eachUrl.contains("www.") || eachUrl.contains("http"))) {
				// eachUrl = "https://" + eachUrl;
				// }
				/* End For No protocal Urls */

				URL inputUrl = new URL(eachUrl);

				String resWrite = "";

				/*
				 * This function finds IP address in URL. Returns -1 if FOUND. Returns 1 if NOT
				 * FOUND.
				 */
				//resWrite += findIP(eachUrl) + ",";
				resWrite += findIP(inputUrl.getHost().toString()) + ",";

				/*
				 * This function finds .exe in URL. Returns -1 if FOUND. Returns 1 if NOT FOUND.
				 */
				//resWrite += findExe(eachUrl) + ",";
				String fnutil=FilenameUtils.getName(inputUrl.getPath()).toString();
				resWrite += findExe(fnutil) + ",";

				/*
				 * This function finds sensitive words in URL. Sensitive words are predefined.
				 * Returns -1 if FOUND. Returns 1 if NOT FOUND.
				 */
				resWrite += findSecureSensitivity(eachUrl, sec_sen_words) + ",";

				/*
				 * This function finds // in URL. Returns -1 if FOUND. Returns 1 if NOT FOUND.
				 */
				resWrite += findDoubleSlash(eachUrl) + ",";

				/*
				 * This function finds www or http in URL's path including key and value.
				 * Returns -1 if FOUND. Returns 1 if NOT FOUND.
				 */
				resWrite += findW3(inputUrl.getFile()) + ",";

				/* NOT-USED 
				 * This function checks the url is a shorten url. Returns -1 if TRUE. Returns 1
				 * if FALSE. Note: this is the same as checking redirection of url.
				 */
				//resWrite += isExpand(eachUrl) + ",";

				/*
				 * This function checks the creation of domain name. If it is longer than 12
				 * months. Returns -1 if FALSE. Returns 1 if TRUE.
				 */
				WhoisTest whois = new WhoisTest();
				String cutURl = inputUrl.getHost();
				if (cutURl.contains("www.")) {
					cutURl = cutURl.substring(4);
				}
				if (whois.isAgeValid(cutURl)) {
					resWrite += 1 + ",";
				} else {
					resWrite += -1 + ",";
				}
				
				/*
				 * Prepare for Entropy This nacount constructs an array of non alphabets' counts
				 * with same size as preprocessed scanning of nonAlphabet[] array from all
				 * phished urls. It stores counts of each non alphabets stored in nonAlphabet[].
				 * Totalnacounts store total number of occurrences of non alphabets in each Url.
				 */
				double[] nacount = new double[nonAlphaNumeric.length];
				double totalnacount = 0.0;
				for (int i = 0; i < nonAlphaNumeric.length; i++) {
					nacount[i] = findNonAlphabet(eachUrl, nonAlphaNumeric[i]);
					totalnacount += nacount[i];
				}
				
				resWrite += calEntropyNonAlphabet(nacount, totalnacount) + ",";

				/*
				 * This function checks '-' in the url Returns count of '-'
				 */
				resWrite += findDashCount(inputUrl.toString()) + ",";

				/*
				 * This function checks '@' in the url Returns count of '@'
				 */
				resWrite += findAtCount(inputUrl.toString()) + ",";

				/*
				 * This function checks '.' in the url Returns count of '.'
				 */
				resWrite += findDotCount(inputUrl.toString()) + ",";

				/*
				 * This function checks if domain is using free hosting services' domains.
				 * Returns -1 if TRUE. Returns 1 if FALSE.
				 */
				resWrite += chkFreeHostServiceUse(inputUrl.getHost().toString()) + ",";

				/*
				 * This function find port number of url. If port is 443, return 1. If port is
				 * 80, return 0. Else return -1.
				 */
				resWrite += findPortNumber(inputUrl.getPort()) + "," ;
				
				//For Phishing ==> 1
				//resWrite += 1 + System.lineSeparator();
				
				//For Legitimate ==> 1
				resWrite += (-1) + System.lineSeparator();

				System.out.print(resWrite);

				resList.add(resWrite);

			}

			for (String feature : resList) {
				bw.write(feature);
			}

			br.close();
			bw.close();

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private int chkFreeHostServiceUse(String domainstr) {
		String[] freehost = { "110mb", "ripway", "superfreehost", "freehostia", "freeweb7", "t35", "awardspace",
				"phpnet", "reewebhostingpro", "prohosts", "freezoka", "000webhost", "atspace" };

		if (domainstr.contains("www.")) {
			domainstr = domainstr.substring(4);
		}
		for (String each : freehost) {
			if (domainstr.contains(each)) {
				return -1;
			}
		}
		return 1;
	}

	private double calEntropyNonAlphabet(double[] nacount, double totalnacount) {
		// TODO Auto-generated method stub
		double eachUrl_entropy = 0.0;

		for (int i = 0; i < nacount.length; i++) {
			if (nacount[i] > 0.0) {
				eachUrl_entropy -= (nacount[i] / totalnacount)
						* (Math.log10(nacount[i] / totalnacount) / Math.log10(2.0));
			}
		}
		return eachUrl_entropy;
	}

	private int findNonAlphabet(String eachUrl, char c) {
		// TODO Auto-generated method stub
		int count = 0;
		char[] urlArr = eachUrl.toCharArray();
		for (int i = 0; i < urlArr.length; i++) {
			if (urlArr[i] == c) {
				count++;
			}
		}
		return count;
	}

	private char[] extractNonAlphaChar(File urlFile) {
		// TODO Auto-generated method stub
		char[] nonalphacharArr = null;

		try {
			BufferedReader br = new BufferedReader(new FileReader(urlFile));
			String urlStr = null;
			HashMap<Character, Integer> hashLst = new HashMap<Character, Integer>();
			while ((urlStr = br.readLine()) != null) {
				// String urlStrEncode=java.net.URLEncoder.encode(urlStr, "UTF-8");

				if (urlStr.contains("www") || urlStr.contains("http")) {
					URL url = new URL(urlStr);
					urlStr = url.getHost() + url.getFile();
				}

				char[] chArr = urlStr.toCharArray();
				for (char ch : chArr) {
					if (!Character.isAlphabetic(ch) && !hashLst.containsKey(ch) && ch != ' ') {
						hashLst.put(ch, 1);
					} else if (!Character.isAlphabetic(ch) && hashLst.containsKey(ch) && ch != ' ') {
						int count = hashLst.get(ch) + 1;
						hashLst.put(ch, count);
					}
				}
			}

			nonalphacharArr = new char[hashLst.size()];
			for (int i = 0; i < hashLst.size(); i++) {
				nonalphacharArr[i] = (char) hashLst.keySet().toArray()[i];
			}
			br.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return nonalphacharArr;
	}

	private char[] extractNonAlphaNumericChar(File exportFromCsv) {
		char[] nonalphanumeric=null;
		Map<String, Character> presence;
		BufferedReader br;
		try {
			br = new BufferedReader(new FileReader(exportFromCsv));
			String label = br.readLine();
			String[] label_arr = label.split(",");
			nonalphanumeric = new char[label_arr.length];

			HashMap<String, Character> non_alpha_numeric_arr = new HashMap<String, Character>() {
				/**
				 * 
				 */
				private static final long serialVersionUID = 1L;

				{
					put("hash_count", '#');
					put("at_count", '@');
					put("dash_count", '-');
					put("dot_count", '.');
					put("dol_count", '$');
					put("asteric_count", '*');
					put("leftparen_count", '(');
					put("rightparen_count", ')');
					put("plus_count", '+');
					put("semicolor_count", ';');
					put("tide_count", '~');
					put("colon_count", ':');
					put("apos_count", '\'');
					put("slash_count", '/');
					put("percentage_count", '%');
					put("quest_count", '?');
					put("comma_count", ',');
					put("equ_count", '=');
					put("amper_count", '&');
					put("exclam_count", '!');
					put("under_count", '_');
				}
			};		
			
			for(int i=0;i<label_arr.length;i++) {
				if(non_alpha_numeric_arr.containsKey(label_arr[i])) {
					nonalphanumeric[i]=non_alpha_numeric_arr.get(label_arr[i]);
				}
			}
			System.out.println(nonalphanumeric);

		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return nonalphanumeric;
	}

	private int findDashCount(String str) {
		// TODO Auto-generated method stub
		int count = 0;
		char[] strArr = str.toCharArray();
		for (int i = 0; i < str.length(); i++) {
			if (strArr[i] == '-') {
				count++;
			}
		}

		return count;
	}

	private int findAtCount(String str) {
		// TODO Auto-generated method stub

		int count = 0;
		char[] strArr = str.toCharArray();

		for (int i = 0; i < str.length(); i++) {
			if (strArr[i] == '@') {
				count++;
			}
		}

		return count;
	}

	private int findDotCount(String str) {
		// TODO Auto-generated method stub
		int count = 0;
		char[] strArr = str.toCharArray();

		for (int i = 0; i < str.length(); i++) {
			if (strArr[i] == '.') {
				count++;
			}
		}

		return count;
	}

	private int findDolSignCount(String str) {
		// TODO Auto-generated method stub
		int count = 0;
		char[] strArr = str.toCharArray();

		for (int i = 0; i < str.length(); i++) {
			if (strArr[i] == '$') {
				count++;
			}
		}

		return count;
	}

	private int findIP(String url) throws MalformedURLException {
		// TODO Auto-generated method stub

		Pattern ptn = Pattern.compile("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})");

		// Pattern ptn2=Pattern.compile("0[xX][0-9a-fA-F]");

		Matcher mtch = ptn.matcher(url);

		// Matcher mtch2=ptn2.matcher(url);

		if (mtch.find()) {
			return -1;
		}
		return 1;
	}

	private int findExe(String eachUrl) {
		// TODO Auto-generated method stub

		if (eachUrl.contains(".exe")) {
			return -1;
		}
		return 1;
	}

	private int findSecureSensitivity(String eachUrl, String[] sec_sen_words) {
		// TODO Auto-generated method stub

		for (String ele : sec_sen_words) {

			if (Pattern.compile(Pattern.quote(ele), Pattern.CASE_INSENSITIVE).matcher(eachUrl).find()) {
				return -1;
			}
		}
		return 1;
	}

	private int findDoubleSlash(String eachUrl) {
		// TODO Auto-generated method stub
		// System.out.println(eachUrl);
		if (eachUrl.lastIndexOf("//") > 7) {
			return -1;
		}
		return 1;
	}

	private int findW3(String path) {
		// TODO Auto-generated method stub

		if (Pattern.compile(Pattern.quote("www."), Pattern.CASE_INSENSITIVE).matcher(path).find()
				|| Pattern.compile(Pattern.quote("httpa:"), Pattern.CASE_INSENSITIVE).matcher(path).find()) {
			return -1;
		}
		return 1;
	}

/*	private int isExpand(String eachUrl) throws IOException {
		// TODO Auto-generated method stub
		// UrlExpander expand = new UrlExpander();
		String shortUrl = null;
		shortUrl = UrlExpander.expandUrl(eachUrl);
		if (shortUrl != null) {
			return -1;
		}
		return 1;
	}
*/
	private int findPortNumber(int port) {
		// TODO Auto-generated method stub

		if (port == 443) {
			return 1;// Using HTTPS
		} else if (port == 80) {
			return 0;// Using HTTP
		} else {
			return -1;
		}
	}

	public static void main(String args[]) {

		Extraction_non_alphabets_31_05_2019 extFeat = new Extraction_non_alphabets_31_05_2019();
		
		//FOR IMBALANCED DATASETS
		//File inpFile = new File("in_leg_active1.txt");
		//File inpFile = new File("phish_file.txt");
		
		//FOR BALANCED DTASETS
		//File inpFile = new File("phish_5000_data.txt");
		File inpFile = new File("leg_5000_data.txt");
		
		extFeat.extractFeatures(inpFile);
	}
}
