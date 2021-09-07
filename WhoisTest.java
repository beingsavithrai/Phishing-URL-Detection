package whoIsPackage;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.SocketException;
import java.net.URL;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Scanner;

import org.apache.commons.net.whois.WhoisClient;

public class WhoisTest {
	public static void main(String[] args) {
		String urlstr="http://www.toonhound.com/";

		URL url=null;
		String cutURl=null;
		try {
			url = new URL(urlstr);
			cutURl=url.getHost();
			if(cutURl.contains("www.")) {
				cutURl=cutURl.substring(4);
			}
			
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		WhoisTest obj = new WhoisTest();
		//System.out.println(cutURl);
		boolean b=obj.isAgeValid(cutURl);
	}
	
	public boolean isAgeValid(String url) {
		String res = this.getWhois(url);
		//System.out.print(res);
		Date age = this.getCreationDate(res);
		boolean b = false;
		if (age != null) {
			b = this.chkDate(age);
		}	
		//System.out.println(":"+b);
		return b;
	}

	public boolean chkDate(Date age) {
		Date curDate = new Date(System.currentTimeMillis());
		Calendar curCalendar = Calendar.getInstance();
		curCalendar.setTime(curDate);
		Calendar startCalendar = Calendar.getInstance();
		startCalendar.setTime(age);
		startCalendar.add(Calendar.MONTH, 12);
		return startCalendar.before(curCalendar);
	}

	public Date getCreationDate(String res) {
		Boolean flag = false;
		Scanner s = new Scanner(res);
		String[] splited = null;
		while (s.hasNext()) {
			String ss = null;
			if ((ss = s.nextLine()).contains("Creation Date")) {
				splited = ss.split("\\s+");
				flag = true;
				break;
			} else {
				flag = false;
			}
		}
		Date date = null;
		if (flag) {
			try {
				SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
				date = format.parse(splited[splited.length - 1]);
			} catch (ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return date;
	}

	public String getWhois(String domainName) {
		StringBuilder result = new StringBuilder("");
		WhoisClient whois = new WhoisClient();
		try {
			// default is internic.net
			whois.connect(WhoisClient.DEFAULT_HOST);
			String whoisData1 = whois.query("=" + domainName);
			result.append(whoisData1);
			whois.disconnect();
		} catch (SocketException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return result.toString();
	}
}
