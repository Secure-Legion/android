package com.securelegion.adapters

import android.content.Context
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.TextView
import com.securelegion.R
import com.securelegion.database.entities.Wallet

class WalletAdapter(
    context: Context,
    private val wallets: List<Wallet>
) : ArrayAdapter<Wallet>(context, R.layout.item_wallet_spinner, wallets) {

    override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
        return createView(position, convertView, parent)
    }

    override fun getDropDownView(position: Int, convertView: View?, parent: ViewGroup): View {
        return createView(position, convertView, parent)
    }

    private fun createView(position: Int, convertView: View?, parent: ViewGroup): View {
        val view = convertView ?: LayoutInflater.from(context)
            .inflate(R.layout.item_wallet_spinner, parent, false)

        val wallet = wallets[position]

        val walletNameView = view.findViewById<TextView>(R.id.walletName)
        val walletAddressView = view.findViewById<TextView>(R.id.walletAddress)

        walletNameView.text = wallet.name
        walletAddressView.text = "${wallet.solanaAddress.take(8)}...${wallet.solanaAddress.takeLast(4)}"

        return view
    }
}
