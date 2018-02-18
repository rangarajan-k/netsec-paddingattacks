
import java.io.*;
import java.net.*;
import java.util.*;
import java.lang.*;
import java.math.BigInteger;


class hello{


  public static void main(String[] args)
 
	{
    	
	//random input for xor operation for w/2 trails

	String s1 ="1010101010101010";
	
	String r = s1.substring(14, 16);
	
	BigInteger res, pt1;
	
	//counter variable for incrementing and xoring

	String i="0000000000000001";

	//taking input from user

        Scanner input = new Scanner(System.in);

        //cipher0 for boolean function
	
        String c0 = input.nextLine();
   	
	//cipher1 for boolean function
	
	String c1 = input.nextLine();
                
	// for removing 0x

        if (c0.startsWith("0x"))
	
	 {

            c0 = c0.replaceAll("0x", "");

	 }
	// for removing 0x

	if (c1.startsWith("0x")) 
	
	{

            c1 = c1.replaceAll("0x", "");

	}

	//conversion to int from char
	
	BigInteger i1 = new BigInteger( r, 16);
	BigInteger i2 = new BigInteger( i, 16);
	BigInteger i3 = new BigInteger( c0, 16);
	//BigInteger i4 = new BigInteger( c1, 16);
       	
	//xor
	for (int n=0; n<=255; n++)
	{
	res = i1.xor(i2);
	String pt = res.toString(16);
       	pad_oracle p = new pad_oracle();
	boolean isPaddingCorrect = p.doOracle(pt, c1);
	if(isPaddingCorrect == true)
	break;
	else
	i2 = i2.add(BigInteger.ONE);
	pt1 = res.xor(i3);
	String plaintext = pt1.toString(16);
	System.out.println(plaintext);
	
	}	
	
	        
    }

    }