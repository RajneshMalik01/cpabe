package cp_abe;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Scanner;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;

class makesetup
{
    String pairingDesc; // it will store string value for pairing
    Pairing p;
    Element g; //primary G1 element
	Element f; //Group G1 element
	Element h; //Group G1 element
	Element gp; //primary G2 element
	Element g_alpha;//Group G2 element
	Element g_hat_alpha; //mapped Group element
	Element beta;
    String curveParams = "type a\n"
			+ "q 87807107996633125224377819847540498158068831994142082"
			+ "1102865339926647563088022295707862517942266222142315585"
			+ "8769582317459277713367317481324925129998224791\n"
			+ "h 12016012264891146079388821366740534204802954401251311"
			+ "822919615131047207289359704531102844802183906537786776\n"
			+ "r 730750818665451621361119245571504901405976559617\n"
			+ "exp2 159\n" + "exp1 107\n" + "sign1 1\n" + "sign0 1\n";
    void setup() {
    	PropertiesParameters params = new PropertiesParameters().load(new ByteArrayInputStream(curveParams.getBytes()));/* getBytes return ascii 8 bit value of each digit/char
    	 * ByteArrayInputStream combine all byte values into input stream
    	 * 
    	 */
    	pairingDesc = curveParams;
    	p = PairingFactory.getPairing(params);
    	Pairing pairing = p;
    	g = pairing.getG1().newElement(); //primary G1 element
    	f = pairing.getG1().newElement(); //Group G1 element
    	h = pairing.getG1().newElement(); //Group G1 element
    	gp = pairing.getG2().newElement(); //primary G2 element
    	g_alpha = pairing.getG2().newElement();//Group G2 element
    	g_hat_alpha = pairing.getGT().newElement(); //mapped Group element
    	Element alpha = pairing.getZr().newElement();
    	beta = pairing.getZr().newElement();
    	
    	alpha.setToRandom();
    	beta.setToRandom();
		
		g.setToRandom(); //assigning random value for element g(G1)
		gp.setToRandom();//assigning random value for element gp(G2)
		
		g_alpha = gp.duplicate(); // g_alpha = gp
		g_alpha.powZn(alpha);// g_alpha = gp ^ alpha
	
		Element beta_inv = beta.duplicate();
		beta_inv.invert(); // beta = 1/beta
		f = g.duplicate(); // f = g
		f.powZn(beta_inv); // f = f^(1/beta)
	
		h = g.duplicate(); // h = g
		h.powZn(beta); // h = g^beta
	
		g_hat_alpha = pairing.pairing(g, g_alpha); // mapping of group G1 and G2 into GT
    }

}
class user
{
	String attr;
	Element a;
	Element b;
}

class keygen
{
	Element d;
	ArrayList<user> comps = new ArrayList<user>();
	void secretkey(makesetup ms) {
		Pairing pair;
		pair = ms.p; // ms is object of makesetup class
		d = pair.getG2().newElement();// d is element of Group G2
		Element r = pair.getZr().newElement();
		r.setToRandom(); // Assigned random value to r
		Element gr = pair.getG2().newElement();// gr is element of Group G2
		gr = ms.gp.duplicate(); // gr = gp
		gr.powZn(r); // gr = gp^r
		d.mul(gr); // d = d*gr
		Element bi = pair.getZr().newElement();
		bi = ms.beta.duplicate(); // bi = beta
		bi.invert(); // bi = 1/beta;
		d.powZn(bi);// d = d^(1/beta)
		
		Scanner sc = new Scanner(System.in);
        System.out.println("enter the number of attributes of user");
       
        int n = sc.nextInt(); // Number of Attributes
        sc.nextLine();
        String[] attributes = new String[n]; //array with n capacity
        int i;
        System.out.println("enter the attributes");
        for(i = 0; i < n; i++)
             attributes[i] = sc.nextLine();
        
        System.out.println("the attributes are :");
        for(i = 0; i < n; i++)
             System.out.println(attributes[i]);
        
        System.out.println("FOR EVERY ATTRIBUTE ");
        for(i = 0; i < n; i++)
        {
        	user u = new user(); // u is a user's object
            u.attr = attributes[i]; // user has these attributes
            Element rp = pair.getZr().newElement();
            rp.setToRandom(); // assigning random value to rp
            u.a = pair.getG1().newElement();// user's a of Group G1
            u.b = pair.getG2().newElement();// user's b of Group G2
            u.b = gr.duplicate(); // b = gr 
            Element h = pair.getG2().newElement();// Element h of Group G2
            h.powZn(rp); // h = h^rp
            u.b.mul(h); // b = b*h
            u.a = ms.g.duplicate(); // a = g
            u.a.powZn(rp); // a = a^rp
            comps.add(u);
            System.out.println(u.a);
            System.out.println(u.b); 
        }
	}
}

class polynomial{
	int degree;
	Element[] coef;
}

class policy{
	String attr;
	int k;
	policy[] child;
	Element c1;
	Element c2;
	polynomial q;
	boolean satisfy = false;
}

class ciphertext{
	Element c;
	Element cs;
	policy p;
	Element[] ctext;
	Integer[] ct;
	Element generate_ct(makesetup o) /*method*/{
		Element s;
		Pairing pa = o.p; // pa = p;
		s = pa.getZr().newElement();
		c = pa.getG1().newElement(); // Element c of Group G1
		cs = pa.getGT().newElement(); // Element cs of Group GT
		s.setToRandom(); // assign random to s
		c = o.g_alpha.duplicate(); //c = h
		c.powZn(s); // c = c^s
		
		
		Scanner sc = new Scanner(System.in);
		String message = sc.nextLine();
        int l = message.length();
        ct = new Integer[l];
        for(int i = 0; i < l; i++)
        	ct[i] = (int)message.charAt(i); //ct = ascii value of message
        
        cs = o.g_hat_alpha.duplicate(); // cs = g_hat_alpha
        cs.powZn(s); // cs = cs^s
        
        ctext = new Element[l];
        for(int i = 0; i < l; i++)
        	ctext[i] = cs.mul(ct[i]);
		return s;
	}
	
	policy access_structure(String cipher_policy) {
		String[] toks;
		String tok;
		ArrayList<policy> stack = new ArrayList<>();
		toks = cipher_policy.split(" ");
		int index;
		index = toks.length;
		
		for(int i = 0; i < index; i++) {
			int k,n;
			tok = toks[i];
			if(!tok.contains("of")){
				policy node = new policy();
				node.attr = tok;
				node.k = 1;
				stack.add(node);
			}else{
				String[] again = tok.split("of");
				k = Integer.parseInt(again[0]);
	            n = Integer.parseInt(again[1]);
	            policy node2 = new policy();
	            node2.attr = null;
	            node2.k = k;
	            node2.child = new policy[n];
	            int it;
	            for(it = n - 1; it >= 0; it--){
	            	node2.child[it]=new policy();
	                node2.child[it]=stack.remove(stack.size()-1);
	            }
	            stack.add(node2);
			}
		}
		p = stack.get(0);
		
		return p;
	}
	
	void fillPolicy(policy p, makesetup m, Element e) {
		Pairing pairing = m.p;
		Element r = pairing.getZr().newElement();
		Element t = pairing.getZr().newElement();
		Element h = pairing.getG2().newElement();
		h = m.h.duplicate(); // this h = h
		
		p.q = randPoly(p.k - 1,e);
		
		if (p.child == null || p.child.length == 0) {
			p.c1 = pairing.getG1().newElement();
			p.c2 = pairing.getG2().newElement();

			
			p.c1 = m.g.duplicate();;
			p.c1.powZn(p.q.coef[0]); 	
			p.c2 = h.duplicate();
			p.c2.powZn(p.q.coef[0]);
		} else {
			for (int i = 0; i < p.child.length; i++) {
				r.set(i + 1);
				evalPoly(t, p.q, r);
				fillPolicy(p.child[i], m, t);
			}
		}

	}
    void evalPoly(Element r, polynomial q, Element x) {
		int i;
		Element s, t;

		s = r.duplicate();
		t = r.duplicate();

		r.setToZero();
		t.setToOne();

		for (i = 0; i < q.degree + 1; i++) {
			
			s = q.coef[i].duplicate();
			s.mul(t); 
			r.add(s);

			
			t.mul(x);
		}

	}
     polynomial randPoly(int deg, Element zeroVal) {
		int i;
		polynomial q = new polynomial();
		q.degree = deg;
		q.coef = new Element[deg + 1];

		for (i = 0; i < deg + 1; i++)
			q.coef[i] = zeroVal.duplicate();

		q.coef[0].set(zeroVal);

		for (i = 1; i < deg + 1; i++)
			q.coef[i].setToRandom();

		return q;
	}
}

class dec{
	void decrypt(keygen sk, policy p) {
		if(p.attr!=null) {
			String at = p.attr;
			for(int i = 0; i < sk.comps.size(); i++) {
				if(at.compareTo(sk.comps.get(i).attr) == 0 ) {
					p.satisfy = true;
					return;
				}
			}
		}else {
			for(int i = 0; i < p.child.length;i++)
				decrypt(sk,p.child[i]);
		}
	}
	
	boolean check(policy p) {
		int count = 0;
		for(int i = 0; i < p.child.length; i++) {
			if(p.child[i].satisfy == true)
				count++;
		}
		if(count >= p.k) {
			System.out.println("ACCESS GRANTED");
			return true;
		}else {
			System.out.println("ACCESS GRANTED");
			return false;
		}
	}
	
	void getvalue(ciphertext t, keygen k, makesetup pub) {
		Pairing pair;
		pair = pub.p;
		Element r1 = pair.getG1().newElement(); // r1 of G1
		r1 = k.d.duplicate(); // r1 = d
		Element r2 = pair.getG1().newElement(); // r2 of G1
		r2 = t.c.duplicate(); // r2 = c
		Element r3 = pair.getGT().newElement(); // r3 of GT
		r3 = pair.pairing(r1, r2);
		r3.div(t.cs); // r3 = r3/cs
	}
}
public class Testing 
{
    public static void main( String[] args )
    {
    	//making setup
    	makesetup ob = new makesetup(); // ob object of makesetup
        long time1;
        time1 = System.currentTimeMillis();
        ob.setup();
        long time2 = System.currentTimeMillis();
        System.out.println("time for setup in milli seconds");
        System.out.println(time2 - time1); //runtime for makesetup
        policy root;
        
        //Generating key
        keygen key = new keygen(); //object for generating key
        long keygentime1;
        keygentime1 = System.currentTimeMillis();
        key.secretkey(ob);
        long keygentime2;
        keygentime2 =System.currentTimeMillis();
        System.out.println("time for key generation in milli seconds");
        System.out.println(keygentime2 - keygentime1); // runtime key gen
        
        //generating ciphertext
        ciphertext text = new ciphertext();
        long enc1 = System.currentTimeMillis();
        Element s_p = text.generate_ct(ob);
        long enc12 = System.currentTimeMillis();
        System.out.println(s_p);
        Scanner sc = new Scanner(System.in);
        System.out.println("Enter the cipher policy");
        String s = sc.nextLine(); //Cipher policy
        long enc2 = System.currentTimeMillis();
        text.p = text.access_structure(s);
        System.out.println(text.p.k);
        long enc22 = System.currentTimeMillis();
        long enc3 = System.currentTimeMillis();
        text.fillPolicy(text.p, ob, s_p);
        long enc32 = System.currentTimeMillis();
        int i;
        System.out.println("time for encryption");
        System.out.println((enc12-enc1)+(enc22-enc2)+(enc32-enc3)); // Encryption time
    
        dec d1 = new dec();
        long dect = System.currentTimeMillis();
        d1.decrypt(key,text.p);
        
        boolean x;
      
        x = d1.check(text.p);
        if(x)
        	d1.getvalue(text,key,ob);

        long fdect = System.currentTimeMillis();
        System.out.println("time for decryption");
        System.out.println(fdect-dect);
    }
}


