//
//  ViewController.swift
//  SSLPinning
//
//  Created by Milan Panchal on 09/03/21.
//

import UIKit

class ViewController: UIViewController {
    
    private let serverURL = "https://github.com"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
                
    }

    // MARK:- IBAction methods
    @IBAction func didTapOnSSLPinningPublicKey(sender: UIButton) {

        sslPinningUsingPublicKeys(urlString: serverURL)

    }

    @IBAction func didTapOnSSLPinningCertificate(sender: UIButton) {
        sslPinningUsingCertificate(urlString: serverURL)
    }

    // MARK:- User defined methods
    private func sslPinningUsingCertificate(urlString: String) {

        guard let url = URL(string: urlString) else {
            return
        }

        NetworkManager.shared.callAPI(withURL: url, isCertificatePinning: true) { (message) in
            let alert = UIAlertController(title: "SSLPinning", message: message, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            self.present(alert, animated: true, completion: nil)
        }

    }
    
    private func sslPinningUsingPublicKeys(urlString: String) {

        guard let url = URL(string: urlString) else {
            return
        }

        NetworkManager.shared.callAPI(withURL: url, isCertificatePinning: false) { (message) in
            let alert = UIAlertController(title: "SSLPinning", message: message, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            self.present(alert, animated: true, completion: nil)
        }

    }
    
}
